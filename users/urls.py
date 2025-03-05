from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ChangeEmailView,
    ChangeMobileView,
    ChangePasswordView,
    DeleteUserView,
    LoginView,
    LogoutView,
    RegisterView,
    ResendOTPView,
    ResetPasswordConfirmView,
    ResetPasswordRequestView,
    SellerProfileView,
    SellerVerificationFileDetailView,
    SellerVerificationFileView,
    SocialAccountDisconnectView,
    SocialAccountsView,
    SocialLoginView,
    UserProfileView,
    VerifyOTPView,
)

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # OTP verification endpoints
    path('auth/verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('auth/resend-otp/', ResendOTPView.as_view(), name='resend_otp'),
    # Password management
    path(
        'auth/reset-password/',
        ResetPasswordRequestView.as_view(),
        name='reset_password_request',
    ),
    path(
        'auth/reset-password/confirm/',
        ResetPasswordConfirmView.as_view(),
        name='reset_password_confirm',
    ),
    path(
        'user/change-password/',
        ChangePasswordView.as_view(),
        name='change_password',
    ),
    # User profile management
    path('user/profile/', UserProfileView.as_view(), name='user_profile'),
    path('delete-account/', DeleteUserView.as_view(), name='delete-account'),
    # User contact information management
    path('auth/change-email/', ChangeEmailView.as_view(), name='change_email'),
    path(
        'auth/change-mobile/', ChangeMobileView.as_view(), name='change_mobile'
    ),
    # Social Authentication
    path('auth/social/login/', SocialLoginView.as_view(), name='social-login'),
    path(
        'auth/social/accounts/',
        SocialAccountsView.as_view(),
        name='social-accounts',
    ),
    path(
        'auth/social/disconnect/',
        SocialAccountDisconnectView.as_view(),
        name='social-disconnect',
    ),
    # Seller profile endpoints
    path('seller/profile/', SellerProfileView.as_view(), name='seller_profile'),
    # Verification file endpoints
    path(
        'seller/verification-files/',
        SellerVerificationFileView.as_view(),
        name='verification_files',
    ),
    path(
        'seller/verification-files/<uuid:file_id>/',
        SellerVerificationFileDetailView.as_view(),
        name='verification_file_detail',
    ),
]
