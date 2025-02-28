from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ActivateUserView,
    ChangePasswordView,
    DeleteUserView,
    LoginView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegisterView,
    UserProfileView,
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
]
