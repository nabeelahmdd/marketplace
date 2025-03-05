from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

User = get_user_model()


class ResetPasswordRequestSerializer(serializers.Serializer):
    """Serializer for requesting a password reset.

    Validates that the provided email or mobile number exists in the system
    before initiating the password reset process.
    """

    email = serializers.EmailField(
        required=False, help_text="Email address for password reset"
    )
    mobile = serializers.CharField(
        required=False, help_text="Mobile number for password reset"
    )

    def validate(self, data):
        """Validate that either email or mobile is provided and exists.

        Args:
        ----
            data (dict): The data to validate

        Returns:
        -------
            dict: The validated data

        Raises:
        ------
            serializers.ValidationError: If validation fails
        """
        email = data.get('email')
        mobile = data.get('mobile')

        if not email and not mobile:
            raise serializers.ValidationError(
                _("Either email or mobile must be provided.")
            )

        # Check if user exists with the provided credentials
        if email and not User.objects.filter(email=email).exists():
            # We don't reveal if the email exists or not for security
            # Just return the validated data
            pass
        elif mobile and not User.objects.filter(mobile=mobile).exists():
            # We don't reveal if the mobile exists or not for security
            # Just return the validated data
            pass

        return data


class ResetPasswordConfirmSerializer(serializers.Serializer):
    """Serializer for confirming a password reset.

    Handles validation and processing of password reset confirmations.
    """

    email = serializers.EmailField(
        required=False, help_text="Email for which OTP was sent"
    )
    mobile = serializers.CharField(
        required=False, help_text="Mobile number for which OTP was sent"
    )
    otp = serializers.CharField(
        required=True, min_length=6, max_length=6, help_text="OTP code received"
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="New password to set",
    )

    def validate(self, data):
        """Validate that either email or mobile is provided.

        Args:
        ----
            data (dict): The data to validate

        Returns:
        -------
            dict: The validated data

        Raises:
        ------
            serializers.ValidationError: If validation fails
        """
        email = data.get('email')
        mobile = data.get('mobile')

        if not email and not mobile:
            raise serializers.ValidationError(
                _("Either email or mobile must be provided.")
            )

        return data

    def validate_new_password(self, value):
        """Validate new password against Django's built-in validation rules.

        Args:
        ----
            value (str): The new password to validate

        Returns:
        -------
            str: The validated new password

        Raises:
        ------
            ValidationError: If new password doesn't meet security requirements
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
