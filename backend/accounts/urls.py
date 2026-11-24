from django.urls import path

from .password_reset_views import (
    PasswordResetConfirmView,
    PasswordResetRequestView,
    PasswordResetValidateView,
)
from .sso_views import (
    sso_callback_view,
    sso_config_view,
    sso_link_start_view,
    sso_login_view,
    sso_unlink_view,
)
from .views import (
    RegisterView,
    VerifiedTokenRefreshView,
    login_view,
    logout_view,
    get_user_view,
    UpdateProfileView,
    ChangePasswordView,
    delete_account_view,
    resend_verification_email_view,
    send_verification_email_view,
    verify_email_view,
)

app_name = "accounts"

urlpatterns = [
    # Authentication
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("token/refresh/", VerifiedTokenRefreshView.as_view(), name="token_refresh"),
    path(
        "send-verification-email/",
        send_verification_email_view,
        name="send_verification_email",
    ),
    path(
        "resend-verification-email/",
        resend_verification_email_view,
        name="resend_verification_email",
    ),
    path("verify-email/", verify_email_view, name="verify_email"),
    path(
        "password-reset/request/",
        PasswordResetRequestView.as_view(),
        name="password_reset_request",
    ),
    path(
        "password-reset/validate/",
        PasswordResetValidateView.as_view(),
        name="password_reset_validate",
    ),
    path(
        "password-reset/confirm/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    # Single sign-on (off unless SSO_ENABLED; see accounts/sso.py)
    path("sso/config/", sso_config_view, name="sso_config"),
    path("sso/login/", sso_login_view, name="sso_login"),
    path("sso/callback/", sso_callback_view, name="sso_callback"),
    path("sso/link/", sso_link_start_view, name="sso_link_start"),
    path("sso/unlink/", sso_unlink_view, name="sso_unlink"),
    # User management
    path("user/", get_user_view, name="get_user"),
    path("user/update/", UpdateProfileView.as_view(), name="update_profile"),
    path("user/change-password/", ChangePasswordView.as_view(), name="change_password"),
    path("user/delete/", delete_account_view, name="delete_account"),
]
