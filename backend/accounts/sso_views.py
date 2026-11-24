"""HTTP endpoints for single sign-on. All of them except ``config`` answer 404 while SSO is off."""

import logging
from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.contrib.auth.models import update_last_login
from django.http import Http404, HttpResponseRedirect
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from questizsurvey.audit import log_audit_event

from . import sso
from .throttles import SSORateThrottle
from .token_cookies import set_refresh_cookie
from .verification import get_request_ip_address

logger = logging.getLogger(__name__)

DEFAULT_NEXT = "/dashboard"
SESSION_NEXT_KEY = "sso_next"
SESSION_LINK_USER_KEY = "sso_link_user_id"


def _require_enabled():
    if not sso.is_enabled():
        raise Http404()


def safe_next(value, fallback=DEFAULT_NEXT):
    """Same rule as the frontend's getSafeRedirect: a path on this site, nothing else."""
    target = (value or "").strip()
    if not target.startswith("/") or target.startswith("//") or "\\" in target:
        return fallback
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return fallback
    return target


def _frontend_url(path, params):
    base = (settings.PUBLIC_APP_URL or "").rstrip("/")
    query = urlencode({key: value for key, value in params.items() if value})
    return f"{base}{path}" + (f"?{query}" if query else "")


def _fail(request, code, *, detail="", next_path="", linking=False):
    log_audit_event(
        "sso_login_failure",
        outcome="failure",
        level="warning",
        request=request,
        reason=code,
        detail=detail,
    )
    target = "/profile" if linking else "/login"
    return HttpResponseRedirect(
        _frontend_url(target, {"sso_error": code, "redirect": None if linking else next_path})
    )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def sso_config_view(request):
    return Response(sso.public_config())


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([SSORateThrottle])
def sso_login_view(request):
    """Start sign-in (or profile linking when a one-time ``link_token`` is given)."""
    _require_enabled()
    django_request = request._request
    next_path = safe_next(request.GET.get("next"))

    link_token = request.GET.get("link_token")
    link_user = sso.consume_link_token(link_token) if link_token else None
    if link_token and link_user is None:
        return _fail(request, sso.ERROR_LINK_EXPIRED, linking=True)

    session = django_request.session
    session[SESSION_NEXT_KEY] = next_path
    if link_user is not None:
        session[SESSION_LINK_USER_KEY] = str(link_user.pk)
    else:
        session.pop(SESSION_LINK_USER_KEY, None)

    try:
        return sso.get_client().authorize_redirect(django_request, settings.SSO_REDIRECT_URI)
    except Exception as exc:
        logger.warning("Could not start SSO sign-in.", exc_info=True)
        return _fail(
            request,
            sso.ERROR_PROVIDER,
            detail=exc.__class__.__name__,
            next_path=next_path,
            linking=link_user is not None,
        )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([SSORateThrottle])
def sso_callback_view(request):
    _require_enabled()
    django_request = request._request
    session = django_request.session
    next_path = safe_next(session.get(SESSION_NEXT_KEY))
    link_user_id = session.get(SESSION_LINK_USER_KEY)
    linking = bool(link_user_id)

    try:
        claims = sso.fetch_verified_claims(django_request)
        link_user = None
        if linking:
            link_user = sso.User.objects.filter(pk=link_user_id, is_active=True).first()
            if link_user is None:
                raise sso.SSOError(sso.ERROR_LINK_EXPIRED, "Linking user gone")
        user, outcome = sso.resolve_user(
            claims,
            link_user=link_user,
            registration_ip=get_request_ip_address(request),
        )
    except sso.SSOError as exc:
        session.flush()
        return _fail(request, exc.code, detail=exc.detail, next_path=next_path, linking=linking)

    # The session only carried the flow state; the API itself stays on JWTs.
    session.flush()

    if outcome in {"linked_profile", "linked_email", "created"}:
        log_audit_event(
            "sso_link",
            request=request,
            actor_user=user,
            linked_via=outcome,
            issuer=claims["iss"],
        )

    refresh = RefreshToken.for_user(user)
    refresh[sso.AUTH_METHOD_CLAIM] = sso.AUTH_METHOD_SSO
    update_last_login(None, user)
    log_audit_event("sso_login_success", request=request, actor_user=user, outcome_detail=outcome)

    if linking:
        target = _frontend_url("/profile", {"sso_linked": "1"})
    else:
        target = _frontend_url("/auth/sso/complete", {"next": next_path})
    response = HttpResponseRedirect(target)
    set_refresh_cookie(response, str(refresh))
    return response


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([SSORateThrottle])
def sso_link_start_view(request):
    """Give a signed-in user a one-time URL that links their account to the provider."""
    _require_enabled()
    if sso.linked_identity(request.user) is not None:
        return Response(
            {"detail": "Your account is already linked.", "code": sso.ERROR_ALREADY_LINKED},
            status=status.HTTP_409_CONFLICT,
        )
    token = sso.create_link_token(request.user)
    # The frontend navigates to <API_URL>/auth/sso/login/?link_token=… with it.
    return Response({"link_token": token, "expires_in": sso.LINK_TOKEN_TTL_SECONDS})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def sso_unlink_view(request):
    _require_enabled()
    identity = sso.linked_identity(request.user)
    if identity is None:
        return Response({"detail": "Your account is not linked."}, status=status.HTTP_404_NOT_FOUND)
    if not request.user.has_usable_password():
        return Response(
            {
                "detail": "Set a password first, so you can still sign in after unlinking.",
                "code": "password_required",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    issuer = identity.issuer
    identity.delete()
    log_audit_event("sso_unlink", request=request, actor_user=request.user, issuer=issuer)
    return Response({"detail": "Unlinked."})
