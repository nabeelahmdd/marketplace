from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from users.models import OTP

User = get_user_model()


class RequestPhoneOTPSerializer(serializers.Serializer):
    """Serializer for requesting an OTP via phone."""

    phone = serializers.CharField(
        required=True,
        help_text=_("Phone number with country code (e.g., +919876543210)"),
    )
    country_code = serializers.CharField(
        required=False,
        help_text=_("Country code (e.g., +91). Optional if included in phone."),
    )
    purpose = serializers.ChoiceField(
        choices=OTP.PURPOSE_CHOICES,
        help_text=_("Purpose for which OTP is requested"),
    )

    def validate_phone(self, value):
        """Normalize phone number format."""
        # Remove any spaces or special characters
        phone = ''.join(filter(lambda x: x.isdigit() or x == '+', value))

        # Ensure phone number starts with +
        if not phone.startswith('+'):
            # If country_code is provided separately
            country_code = self.initial_data.get('country_code', '')
            if country_code:
                if not country_code.startswith('+'):
                    country_code = f"+{country_code}"
                phone = f"{country_code}{phone}"
            else:
                raise serializers.ValidationError(
                    _("Phone number must include country code with + prefix")
                )

        return phone


class RequestEmailOTPSerializer(serializers.Serializer):
    """Serializer for requesting an OTP via email."""

    email = serializers.EmailField(
        required=True, help_text=_("Email address to send OTP to")
    )
    purpose = serializers.ChoiceField(
        choices=OTP.PURPOSE_CHOICES,
        help_text=_("Purpose for which OTP is requested"),
    )

    def validate_email(self, value):
        """Normalize email to lowercase."""
        return value.lower()


class VerifyOTPSerializer(serializers.Serializer):
    """Serializer for verifying an OTP."""

    identifier = serializers.CharField(
        required=True,
        help_text=_("Phone number or email for which OTP was generated"),
    )
    otp = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text=_("OTP code to verify"),
    )
    purpose = serializers.ChoiceField(
        choices=OTP.PURPOSE_CHOICES,
        help_text=_("Purpose for which OTP was generated"),
    )

    def validate_otp(self, value):
        """Ensure OTP is numeric and of correct length."""
        if not value.isdigit():
            raise serializers.ValidationError(_("OTP must contain only digits"))
        return value


class OTPRegisterSerializer(serializers.Serializer):
    """Serializer for registering a user with OTP verification."""

    phone = serializers.CharField(
        required=True, help_text=_("Phone number with country code")
    )
    country_code = serializers.CharField(
        required=False,
        help_text=_("Country code (e.g., +91). Optional if included in phone."),
    )
    otp = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text=_("OTP code received"),
    )
    email = serializers.EmailField(
        required=False,
        help_text=_("Email address (optional for phone-only registration)"),
    )
    first_name = serializers.CharField(
        required=False, help_text=_("User's first name")
    )
    last_name = serializers.CharField(
        required=False, help_text=_("User's last name")
    )

    def validate_phone(self, value):
        """Normalize phone number format."""
        # Remove any spaces or special characters
        phone = ''.join(filter(lambda x: x.isdigit() or x == '+', value))

        # Ensure phone number starts with +
        if not phone.startswith('+'):
            # If country_code is provided separately
            country_code = self.initial_data.get('country_code', '')
            if country_code:
                if not country_code.startswith('+'):
                    country_code = f"+{country_code}"
                phone = f"{country_code}{phone}"
            else:
                raise serializers.ValidationError(
                    _("Phone number must include country code with + prefix")
                )

        # Check if phone is already registered with an active user
        if User.objects.filter(
            mobile=phone, is_active=True, is_deleted=False
        ).exists():
            raise serializers.ValidationError(
                _("This phone number is already registered")
            )

        return phone

    def validate_otp(self, value):
        """Ensure OTP is numeric."""
        if not value.isdigit():
            raise serializers.ValidationError(_("OTP must contain only digits"))
        return value

    def validate_email(self, value):
        """Normalize and validate email."""
        if value:
            email = value.lower()
            # Check if email is already registered with an active user
            if User.objects.filter(
                email=email, is_active=True, is_deleted=False
            ).exists():
                raise serializers.ValidationError(
                    _("This email is already registered")
                )
            return email
        return None


class OTPLoginSerializer(serializers.Serializer):
    """Serializer for logging in with OTP verification."""

    # Make phone optional
    phone = serializers.CharField(
        required=False, help_text=_("Phone number with country code")
    )
    country_code = serializers.CharField(
        required=False,
        help_text=_("Country code (e.g., +91). Optional if included in phone."),
    )
    # Add email field
    email = serializers.EmailField(
        required=False, help_text=_("Email address for OTP login")
    )
    otp = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text=_("OTP code received"),
    )

    def validate(self, data):
        """Validate that either phone or email is provided."""
        if not data.get('phone') and not data.get('email'):
            raise serializers.ValidationError(
                _("Either phone or email is required")
            )
        return data

    def validate_email(self, value):
        """Normalize and validate email."""
        if value:
            email = value.lower()
            # Check if email exists in the system
            if not User.objects.filter(
                email=email, is_active=True, is_deleted=False
            ).exists():
                raise serializers.ValidationError(
                    _("No account found with this email")
                )
            return email
        return None
