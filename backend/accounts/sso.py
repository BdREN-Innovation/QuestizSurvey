"""Single sign-on through an external OpenID Connect provider.

Everything here is driven by the ``SSO_*`` settings (environment variables). The provider is
generic OIDC; bdren.ai's ZITADEL is simply the configured one. Users are matched by the token's
(issuer, subject) through :class:`ExternalIdentity`, never by email, except for the opt-in
``SSO_LINK_BY_VERIFIED_EMAIL`` migration path.
"""

import base64
import json
import logging
import re
import secrets
import threading
import time
from datetime import timedelta

from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.contrib.auth import get_user_model

from .models import ExternalIdentity, SsoSession

logger = logging.getLogger(__name__)
User = get_user_model()

CLIENT_NAME = "sso"
ALLOWED_ID_TOKEN_ALGORITHMS = {"RS256"}
ID_TOKEN_LEEWAY_SECONDS = 30
LINK_TOKEN_TTL_SECONDS = 5 * 60
LINK_TOKEN_CACHE_PREFIX = "sso:link:"
AUTH_METHOD_CLAIM = "auth_method"
AUTH_METHOD_SSO = "sso"
# Questiz tokens from an SSO sign-in carry the SsoSession id under this claim.
SSO_SESSION_CLAIM = "sso_session"
SESSION_STATE_CACHE_PREFIX = "sso:session:"
SESSION_ACTIVE_CACHE_SECONDS = 60
SESSION_ENDED_CACHE_SECONDS = 24 * 60 * 60
SESSION_SEEN_UPDATE_SECONDS = 60 * 60
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
LOGOUT_TOKEN_MAX_AGE_SECONDS = 30 * 60
LOGOUT_JTI_CACHE_PREFIX = "sso:logout-jti:"
JWKS_REFRESH_CACHE_KEY = "sso:jwks-forced-refresh"
JWKS_REFRESH_MIN_INTERVAL_SECONDS = 5 * 60


class SSOError(Exception):
    """A sign-in failure. ``code`` is shown to the frontend; ``detail`` is for logs only."""

    def __init__(self, code, detail=""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


# Error codes the frontend knows how to explain.
ERROR_PROVIDER = "provider_error"
ERROR_STATE = "state_mismatch"
ERROR_TOKEN = "invalid_token"
ERROR_EMAIL_UNVERIFIED = "email_unverified"
ERROR_EMAIL_IN_USE = "email_in_use"
ERROR_SIGNUP_DISABLED = "signup_disabled"
ERROR_ACCOUNT_DISABLED = "account_disabled"
ERROR_IDENTITY_TAKEN = "identity_linked_elsewhere"
ERROR_ALREADY_LINKED = "already_linked"
ERROR_LINK_EXPIRED = "link_expired"


def is_enabled():
    return bool(getattr(settings, "SSO_ENABLED", False))


def public_config():
    return {
        "enabled": is_enabled(),
        "label": settings.SSO_PROVIDER_LABEL if is_enabled() else "",
        "allow_signup": bool(settings.SSO_ALLOW_SIGNUP) if is_enabled() else False,
    }


# --- Authlib client ---------------------------------------------------------------------------

_client_lock = threading.Lock()
_client_cache = {}


def _client_config_key():
    return (
        settings.SSO_ISSUER,
        settings.SSO_CLIENT_ID,
        settings.SSO_CLIENT_SECRET,
        settings.SSO_SCOPES,
        settings.SSO_HTTP_TIMEOUT,
    )


def get_client():
    """The Authlib client for the configured provider (rebuilt when the settings change)."""
    key = _client_config_key()
    with _client_lock:
        client = _client_cache.get(key)
        if client is None:
            oauth = OAuth()
            oauth.register(
                name=CLIENT_NAME,
                client_id=settings.SSO_CLIENT_ID,
                client_secret=settings.SSO_CLIENT_SECRET,
                server_metadata_url=f"{settings.SSO_ISSUER}/.well-known/openid-configuration",
                client_kwargs={
                    "scope": settings.SSO_SCOPES,
                    "code_challenge_method": "S256",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "default_timeout": settings.SSO_HTTP_TIMEOUT,
                },
            )
            client = oauth.create_client(CLIENT_NAME)
            _client_cache.clear()
            _client_cache[key] = client
        return client


def _id_token_header(id_token):
    try:
        header_segment = id_token.split(".")[0]
        padded = header_segment + "=" * (-len(header_segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, IndexError, AttributeError) as exc:
        raise SSOError(ERROR_TOKEN, "Malformed id_token header") from exc


def fetch_verified_claims(request):
    """Finish the authorization-code flow and return the verified ID token claims.

    Authlib checks state (single use, bound to this browser's session), PKCE, the token's
    signature against the provider's JWKS, ``aud``/``azp``, ``exp``, ``iat`` and ``nonce``.
    On top of that we pin the issuer to SSO_ISSUER and allow RS256 only.
    """
    from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
    from joserfc.errors import JoseError

    client = get_client()
    issuer = settings.SSO_ISSUER
    try:
        token = client.authorize_access_token(
            request,
            claims_options={
                "iss": {"essential": True, "values": [issuer]},
                "sub": {"essential": True},
                "aud": {"essential": True},
                "exp": {"essential": True},
            },
            leeway=ID_TOKEN_LEEWAY_SECONDS,
        )
    except MismatchingStateError as exc:
        raise SSOError(ERROR_STATE, "State missing, reused or from another browser") from exc
    except OAuthError as exc:
        raise SSOError(ERROR_PROVIDER, f"Provider error: {exc.error}") from exc
    except JoseError as exc:
        raise SSOError(ERROR_TOKEN, f"id_token rejected: {exc.__class__.__name__}") from exc
    except SSOError:
        raise
    except Exception as exc:  # network errors, bad metadata, non-JSON responses
        raise SSOError(ERROR_PROVIDER, f"Provider request failed: {exc.__class__.__name__}") from exc

    id_token = (token or {}).get("id_token")
    claims = (token or {}).get("userinfo")
    if not id_token or not claims:
        raise SSOError(ERROR_TOKEN, "No verified id_token in the token response")

    alg = _id_token_header(id_token).get("alg")
    if alg not in ALLOWED_ID_TOKEN_ALGORITHMS:
        raise SSOError(ERROR_TOKEN, f"Disallowed id_token algorithm {alg!r}")

    claims = dict(claims)
    if claims.get("iss") != issuer or not str(claims.get("sub") or "").strip():
        raise SSOError(ERROR_TOKEN, "Issuer or subject missing")
    # Kept on the request (never stored) so the bdren.ai allowance call at sign-in can pass it.
    request.sso_id_token = id_token
    return claims


def build_logout_url():
    """RP-initiated logout URL at the provider, or '' when not configured or not offered."""
    if not (is_enabled() and settings.SSO_RP_LOGOUT):
        return ""
    try:
        metadata = get_client().load_server_metadata()
    except Exception:
        logger.warning("Could not load SSO metadata for logout.", exc_info=True)
        return ""
    endpoint = metadata.get("end_session_endpoint")
    if not endpoint:
        return ""
    from urllib.parse import urlencode

    params = {"client_id": settings.SSO_CLIENT_ID}
    post_logout = settings.SSO_POST_LOGOUT_REDIRECT_URI or (
        f"{settings.PUBLIC_APP_URL}/login" if settings.PUBLIC_APP_URL else ""
    )
    if post_logout:
        params["post_logout_redirect_uri"] = post_logout
    return f"{endpoint}?{urlencode(params)}"


# --- Profile linking tokens -------------------------------------------------------------------


def create_link_token(user):
    """One-time token that lets a full-page navigation start linking for ``user``."""
    token = secrets.token_urlsafe(32)
    cache.set(f"{LINK_TOKEN_CACHE_PREFIX}{token}", str(user.pk), LINK_TOKEN_TTL_SECONDS)
    return token


def consume_link_token(token):
    token = (token or "").strip()
    if not token:
        return None
    key = f"{LINK_TOKEN_CACHE_PREFIX}{token}"
    user_id = cache.get(key)
    cache.delete(key)
    if not user_id:
        return None
    return User.objects.filter(pk=user_id, is_active=True).first()


# --- Provisioning -----------------------------------------------------------------------------

_USERNAME_STRIP = re.compile(r"[^\w.@+-]+")


def _unique_username(email, claims):
    base = (claims.get("preferred_username") or "").split("@")[0] or (email or "").split("@")[0]
    base = _USERNAME_STRIP.sub("", base)[:140] or "user"
    candidate = base
    suffix = 2
    while User.objects.filter(username__iexact=candidate).exists():
        candidate = f"{base[:140]}-{suffix}"
        suffix += 1
    return candidate


def _claim_email(claims):
    return (claims.get("email") or "").strip()


def _claim_email_verified(claims):
    value = claims.get("email_verified")
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return value is True


def _profile_from_claims(claims):
    profile = {
        "first_name": (claims.get("given_name") or "")[:150],
        "last_name": (claims.get("family_name") or "")[:150],
    }
    if not profile["first_name"] and not profile["last_name"] and claims.get("name"):
        first, _, last = str(claims["name"]).partition(" ")
        profile["first_name"], profile["last_name"] = first[:150], last[:150]
    organization_claim = settings.SSO_CLAIM_ORGANIZATION
    if organization_claim and isinstance(claims.get(organization_claim), str):
        profile["organization"] = claims[organization_claim][:255]
    return profile


def _ensure_user_can_sign_in(user, claims):
    if not user.is_active:
        raise SSOError(ERROR_ACCOUNT_DISABLED, "User is inactive")
    if user.email_verified:
        return
    # The provider vouches for this address: accept it as verified for the same email.
    if _claim_email_verified(claims) and _claim_email(claims).lower() == (user.email or "").lower():
        user.email_verified = True
        user.save(update_fields=["email_verified", "updated_at"])
        return
    from .verification import is_email_verification_required

    if is_email_verification_required():
        raise SSOError(ERROR_EMAIL_UNVERIFIED, "Local email not verified")


def _attach_identity(user, claims, linked_via):
    try:
        with transaction.atomic():
            return ExternalIdentity.objects.create(
                user=user,
                issuer=claims["iss"],
                subject=str(claims["sub"]),
                email_at_link=_claim_email(claims)[:254],
                linked_via=linked_via,
                last_login_at=timezone.now(),
            )
    except IntegrityError as exc:
        # Either the identity was linked meanwhile, or this user already has one for the issuer.
        if ExternalIdentity.objects.filter(issuer=claims["iss"], subject=str(claims["sub"])).exists():
            raise SSOError(ERROR_IDENTITY_TAKEN, "Identity already linked") from exc
        raise SSOError(ERROR_ALREADY_LINKED, "User already linked to this provider") from exc


def resolve_user(claims, *, link_user=None, registration_ip=None):
    """Return ``(user, outcome)`` for verified claims.

    ``outcome`` is one of ``login``, ``linked_profile``, ``linked_email`` or ``created``.
    Raises :class:`SSOError` when the person may not sign in.
    """
    issuer, subject = claims["iss"], str(claims["sub"])
    identity = (
        ExternalIdentity.objects.select_related("user").filter(issuer=issuer, subject=subject).first()
    )

    if link_user is not None:
        if identity is not None:
            if identity.user_id == link_user.pk:
                return link_user, "login"
            raise SSOError(ERROR_IDENTITY_TAKEN, "Identity linked to another user")
        if ExternalIdentity.objects.filter(user=link_user, issuer=issuer).exists():
            raise SSOError(ERROR_ALREADY_LINKED, "User already linked to this provider")
        _ensure_user_can_sign_in(link_user, claims)
        _attach_identity(link_user, claims, ExternalIdentity.LinkedVia.PROFILE)
        return link_user, "linked_profile"

    if identity is not None:
        user = identity.user
        _ensure_user_can_sign_in(user, claims)
        identity.last_login_at = timezone.now()
        identity.save(update_fields=["last_login_at"])
        return user, "login"

    email = _claim_email(claims)
    email_verified = _claim_email_verified(claims)
    existing = User.objects.filter(email__iexact=email).first() if email else None

    if existing is not None:
        if (
            settings.SSO_LINK_BY_VERIFIED_EMAIL
            and email_verified
            and existing.email_verified
            and existing.is_active
        ):
            if ExternalIdentity.objects.filter(user=existing, issuer=issuer).exists():
                raise SSOError(ERROR_ALREADY_LINKED, "Email owner already linked to another identity")
            _attach_identity(existing, claims, ExternalIdentity.LinkedVia.VERIFIED_EMAIL)
            return existing, "linked_email"
        raise SSOError(ERROR_EMAIL_IN_USE, "Email belongs to an unlinked local account")

    if not settings.SSO_ALLOW_SIGNUP:
        raise SSOError(ERROR_SIGNUP_DISABLED, "New accounts through SSO are disabled")
    if not email:
        raise SSOError(ERROR_TOKEN, "No email claim; add the 'email' scope")
    if not email_verified:
        raise SSOError(ERROR_EMAIL_UNVERIFIED, "Provider email not verified")

    try:
        with transaction.atomic():
            user = User(
                username=_unique_username(email, claims),
                email=email,
                email_verified=True,
                registration_ip=registration_ip or None,
                **_profile_from_claims(claims),
            )
            user.set_unusable_password()
            user.save()
            _attach_identity(user, claims, ExternalIdentity.LinkedVia.SIGNUP)
    except IntegrityError as exc:
        # A concurrent first sign-in for the same person or email won the race.
        identity = ExternalIdentity.objects.select_related("user").filter(
            issuer=issuer, subject=subject
        ).first()
        if identity is not None:
            return identity.user, "login"
        raise SSOError(ERROR_EMAIL_IN_USE, "Email taken concurrently") from exc
    return user, "created"


def linked_identity(user):
    """The user's identity at the configured provider, or None."""
    if not is_enabled() or not getattr(user, "pk", None):
        return None
    return ExternalIdentity.objects.filter(user=user, issuer=settings.SSO_ISSUER).first()


# --- Sign-in sessions and back-channel logout --------------------------------------------------
#
# The provider tells us a session ended by POSTing a signed logout token (OpenID Connect
# Back-Channel Logout 1.0). We keep one SsoSession row per SSO sign-in, tag the Questiz tokens
# with its id, and refuse tokens of an ended row on every API call and on refresh.


def start_session(user, claims):
    """Record a new SSO sign-in and return its SsoSession. Also prunes the user's stale rows."""
    now = timezone.now()
    stale_before = now - settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"] - timedelta(days=1)
    SsoSession.objects.filter(user=user, last_seen_at__lt=stale_before).delete()
    return SsoSession.objects.create(
        user=user,
        issuer=claims["iss"],
        subject=str(claims["sub"]),
        sid=str(claims.get("sid") or "")[:255],
    )


def _session_cache_key(session_id):
    return f"{SESSION_STATE_CACHE_PREFIX}{session_id}"


def is_session_ended(session_id):
    """True when the SSO session behind a Questiz token was ended (or no longer exists)."""
    if not session_id:
        return False
    key = _session_cache_key(session_id)
    state = cache.get(key)
    if state is None:
        try:
            row = SsoSession.objects.filter(pk=session_id).values("ended_at").first()
        except (ValueError, TypeError, DjangoValidationError):
            row = None
        state = "active" if row and row["ended_at"] is None else "ended"
        timeout = SESSION_ACTIVE_CACHE_SECONDS if state == "active" else SESSION_ENDED_CACHE_SECONDS
        cache.set(key, state, timeout)
    return state == "ended"


def touch_session(session_id):
    """Note that a session is still in use (at most hourly), so pruning keeps it."""
    if not session_id:
        return
    cutoff = timezone.now() - timedelta(seconds=SESSION_SEEN_UPDATE_SECONDS)
    try:
        SsoSession.objects.filter(pk=session_id, last_seen_at__lt=cutoff).update(
            last_seen_at=timezone.now()
        )
    except (ValueError, TypeError, DjangoValidationError):
        pass


def _load_jwk_set(force=False):
    from joserfc.jwk import KeySet

    return KeySet.import_key_set(get_client().fetch_jwk_set(force=force))


def _decode_logout_token(raw_token):
    from joserfc import jwt
    from joserfc.errors import JoseError

    header = _id_token_header(raw_token)
    if header.get("alg") not in ALLOWED_ID_TOKEN_ALGORITHMS:
        raise SSOError(ERROR_TOKEN, f"Disallowed logout token algorithm {header.get('alg')!r}")
    try:
        key_set = _load_jwk_set()
        kid = header.get("kid")
        if kid and not any(key.kid == kid for key in key_set.keys):
            # The provider rotated its signing key. Refetch, but not on every forged token.
            if cache.add(JWKS_REFRESH_CACHE_KEY, 1, JWKS_REFRESH_MIN_INTERVAL_SECONDS):
                key_set = _load_jwk_set(force=True)
        return jwt.decode(raw_token, key_set, algorithms=sorted(ALLOWED_ID_TOKEN_ALGORITHMS)).claims
    except JoseError as exc:
        raise SSOError(ERROR_TOKEN, f"Logout token rejected: {exc.__class__.__name__}") from exc
    except SSOError:
        raise
    except Exception as exc:  # unknown kid, network errors, bad JWKS
        raise SSOError(ERROR_TOKEN, f"Logout token not verified: {exc.__class__.__name__}") from exc


def verify_logout_token(raw_token):
    """Verify a back-channel logout token and return its claims, or raise SSOError.

    Checks (Back-Channel Logout 1.0, section 2.6): RS256 signature against the provider's JWKS,
    ``iss``, ``aud`` contains our client id, ``iat`` recent, ``exp`` if present, a ``jti`` not
    seen before, the logout event, no ``nonce``, and at least one of ``sub``/``sid``.
    """
    raw_token = (raw_token or "").strip()
    if not raw_token or raw_token.count(".") != 2:
        raise SSOError(ERROR_TOKEN, "Missing or malformed logout token")
    claims = dict(_decode_logout_token(raw_token))

    now = int(time.time())
    leeway = ID_TOKEN_LEEWAY_SECONDS
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else list(audience or [])
    iat, exp = claims.get("iat"), claims.get("exp")
    events = claims.get("events")
    problems = [
        (claims.get("iss") != settings.SSO_ISSUER, "issuer"),
        (settings.SSO_CLIENT_ID not in audiences, "audience"),
        (not isinstance(iat, (int, float)), "iat missing"),
        (isinstance(iat, (int, float)) and iat > now + leeway, "iat in the future"),
        (isinstance(iat, (int, float)) and now - iat > LOGOUT_TOKEN_MAX_AGE_SECONDS, "iat too old"),
        (exp is not None and (not isinstance(exp, (int, float)) or exp < now - leeway), "expired"),
        (not str(claims.get("jti") or "").strip(), "jti missing"),
        (not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events, "logout event"),
        ("nonce" in claims, "nonce present"),
        (not claims.get("sub") and not claims.get("sid"), "no sub or sid"),
    ]
    for failed, reason in problems:
        if failed:
            raise SSOError(ERROR_TOKEN, f"Logout token invalid: {reason}")

    if not cache.add(f"{LOGOUT_JTI_CACHE_PREFIX}{claims['jti']}", 1, LOGOUT_TOKEN_MAX_AGE_SECONDS * 2):
        raise SSOError(ERROR_TOKEN, "Logout token replayed")
    return claims


def end_sessions(claims):
    """End the SSO sessions a verified logout token names. Returns how many were ended.

    With ``sid``: that provider session only (and, if the provider left ``sid`` out of the
    id_token at sign-in, the subject's sessions recorded without one). Without ``sid``: every
    session of the subject.
    """
    issuer = claims["iss"]
    sid = str(claims.get("sid") or "")
    subject = str(claims.get("sub") or "")
    open_sessions = SsoSession.objects.filter(issuer=issuer, ended_at__isnull=True)

    if sid:
        matched = open_sessions.filter(sid=sid)
        if subject:
            matched = matched.filter(subject=subject)
            without_sid = open_sessions.filter(subject=subject, sid="")
            matched = matched | without_sid
    else:
        matched = open_sessions.filter(subject=subject)

    session_ids = list(matched.values_list("id", flat=True))
    if not session_ids:
        return 0
    SsoSession.objects.filter(pk__in=session_ids).update(ended_at=timezone.now())
    for session_id in session_ids:
        cache.set(_session_cache_key(session_id), "ended", SESSION_ENDED_CACHE_SECONDS)
    return len(session_ids)
