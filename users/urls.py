from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ActivateUserView,
    ChangePasswordView,
    DeleteUserView,
    LoginView,
    OTPLoginView,
    OTPRegisterView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegisterView,
    RequestEmailOTPView,
    RequestPhoneOTPView,
    UserProfileView,
    VerifyOTPView,
)

urlpatterns = [
    # Authentication
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # User Management
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('delete-account/', DeleteUserView.as_view(), name='delete-account'),
    path(
        'change-password/', ChangePasswordView.as_view(), name='change-password'
    ),
    # Password Reset
    path(
        'password-reset/request/',
        PasswordResetRequestView.as_view(),
        name='password-reset-request',
    ),
    path(
        'password-reset/confirm/',
        PasswordResetConfirmView.as_view(),
        name='password-reset-confirm',
    ),
    # Account activation URL
    path('activate/', ActivateUserView.as_view(), name='activate-account'),
    # OTP Generation
    path(
        'otp/phone/request/',
        RequestPhoneOTPView.as_view(),
        name='request-phone-otp',
    ),
    path(
        'otp/email/request/',
        RequestEmailOTPView.as_view(),
        name='request-email-otp',
    ),
    # OTP Verification
    path('otp/verify/', VerifyOTPView.as_view(), name='verify-otp'),
    # OTP-based Authentication
    path('otp/register/', OTPRegisterView.as_view(), name='otp-register'),
    path('otp/login/', OTPLoginView.as_view(), name='otp-login'),
]
