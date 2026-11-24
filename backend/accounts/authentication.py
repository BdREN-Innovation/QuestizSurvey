"""JWT authentication that also honours SSO back-channel logout."""

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

from . import sso

SSO_SESSION_ENDED_DETAIL = "Your bdren.ai sign-in has ended. Please sign in again."


class SsoAwareJWTAuthentication(JWTAuthentication):
    """Standard JWT authentication, except tokens from an ended SSO session are refused.

    Tokens from an SSO sign-in carry the ``sso_session`` claim; the provider can end that
    session through back-channel logout (see ``accounts/sso.py``). Password tokens are untouched.
    """

    def get_user(self, validated_token):
        if sso.is_session_ended(validated_token.get(sso.SSO_SESSION_CLAIM)):
            raise AuthenticationFailed(SSO_SESSION_ENDED_DETAIL, code="sso_session_ended")
        return super().get_user(validated_token)
