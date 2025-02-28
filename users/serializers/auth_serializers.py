from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

User = get_user_model()


class ResetPasswordRequestSerializer(serializers.Serializer):
    """Serializer for requesting a password reset.

    Validates the email address format and existence.
    """

    email = serializers.EmailField(
        required=True, help_text=_("Email address associated with your account")
    )

    def validate_email(self, value):
        """Normalize email to lowercase."""
        return value.lower()


class ResetPasswordConfirmSerializer(serializers.Serializer):
    """Serializer for confirming a password reset.

    Validates the UID, token, and new password.
    """

    uid = serializers.CharField(
        required=True, help_text=_("User ID encoded in base64")
    )
    token = serializers.CharField(
        required=True, help_text=_("Password reset token")
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text=_("New password to set"),
    )

    def validate_new_password(self, value):
        """Validate that the new password meets
        complexity requirements.
        """
        validate_password(value)
        return value


class ActivateAccountSerializer(serializers.Serializer):
    """Serializer for activating a user account.

    Validates the UID and token.
    """

    uidb64 = serializers.CharField(
        required=True, help_text=_("User ID encoded in base64")
    )
    token = serializers.CharField(
        required=True, help_text=_("Account activation token")
    )
