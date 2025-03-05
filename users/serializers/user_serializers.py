import logging

from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import OTP, User

# Initialize logger
logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user registration, profile updates, and retrieving
    user details.

    This serializer handles the conversion between User model instances and JSON
    representation, with special handling for password hashing during user
    creation.

    Attributes
    ----------
        name (CharField): Required full name of the user
        email (EmailField): Optional unique email identifier for the user
        mobile (CharField): Optional unique mobile number with validation
        password (CharField): User's password (write-only)
    """

    class Meta:
        model = User
        fields = [
            'id',
            'name',
            'email',
            'mobile',
            'password',
            'profile_image',
            'is_verified',
            'date_joined',
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True},
            'is_verified': {'read_only': True},
            'date_joined': {'read_only': True},
        }

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
            serializers.ValidationError: If neither email nor mobile is provided
        """
        if not data.get('email') and not data.get('mobile'):
            raise serializers.ValidationError(
                _("Either email or mobile must be provided.")
            )
        return data

    def validate_email(self, value):
        """Validate that the email is unique and properly formatted.

        Args:
        ----
            value (str): The email to validate

        Returns:
        -------
            str: The validated email

        Raises:
        ------
            serializers.ValidationError: If email validation fails
        """
        if value:
            return value.lower()  # Normalize email to lowercase
        return value

    def validate_password(self, value):
        """Validate password against Django's built-in validation rules.

        Args:
        ----
            value (str): The password to validate

        Returns:
        -------
            str: The validated password

        Raises:
        ------
            ValidationError: If password doesn't meet security requirements
        """
        validate_password(value)
        return value

    def create(self, validated_data):
        """Create a new user with hashed password and default settings.

        Args:
        ----
            validated_data (dict): Validated data from request

        Returns:
        -------
            User: Newly created user instance
        """
        # Create user with hashed password
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()

        logger.info(f"New user registered: {user.email or user.mobile}")
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile information.

    This serializer handles updates to user profile data, excluding sensitive
    fields like password which require special workflows.

    Attributes
    ----------
        name (CharField): User's full name
        email (EmailField): User's email address (read-only)
        mobile (CharField): User's mobile number (read-only)
        profile_image (ImageField): User's profile picture
    """

    class Meta:
        model = User
        fields = [
            'name',
            'email',
            'mobile',
            'profile_image',
            'location',
        ]
        extra_kwargs = {
            'email': {'read_only': True},
            'mobile': {'read_only': True},
        }

    def update(self, instance, validated_data):
        """Update user profile with validated data.

        Args:
        ----
            instance (User): The user instance to update
            validated_data (dict): Validated data from request

        Returns:
        -------
            User: Updated user instance
        """
        # Update user profile fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        logger.info(
            f"User profile updated: {instance.email or instance.mobile}"
        )
        return instance


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing user password.

    Handles the validation and processing of password change requests,
    requiring both the old password (for verification) and new password.

    Attributes
    ----------
        old_password (CharField): User's current password for verification
        new_password (CharField): User's desired new password
    """

    old_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="Current password for verification",
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="New password to set",
    )

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

        # Ensure new password differs from old password
        if self.initial_data.get('old_password') == value:
            raise serializers.ValidationError(
                _("New password must be different from the old password.")
            )

        return value


class LoginSerializer(serializers.Serializer):
    """Serializer for user login authentication.

    Handles the validation of user credentials during login process.
    Supports login with either email or mobile number + password.

    Attributes
    ----------
        email (EmailField): User's email address (optional)
        mobile (CharField): User's mobile number (optional)
        password (CharField): User's password (write-only)
    """

    email = serializers.EmailField(
        required=False, help_text="Email address for login"
    )
    mobile = serializers.CharField(
        required=False, help_text="Mobile number for login"
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text="Password for authentication",
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
            serializers.ValidationError: If neither email nor mobile is provided
        """
        if not data.get('email') and not data.get('mobile'):
            raise serializers.ValidationError(
                _("Either email or mobile must be provided.")
            )
        return data

    def validate_email(self, value):
        """Normalize email to lowercase for case-insensitive login."""
        if value:
            return value.lower()
        return value


class UserSerializerWithToken(UserSerializer):
    """Extended User Serializer that includes JWT access token.

    This serializer adds a token field to the standard user serializer
    for returning authentication tokens along with user data after
    successful authentication.

    Attributes
    ----------
        token (SerializerMethodField): JWT access token for authentication
        refresh (SerializerMethodField): JWT refresh token for refreshing \
            access token
    """

    token = serializers.SerializerMethodField(read_only=True)
    refresh = serializers.SerializerMethodField(read_only=True)

    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + ['token', 'refresh']

    def get_token(self, obj):
        """Generate JWT access token for the authenticated user.

        Args:
        ----
            obj (User): User instance to generate token for

        Returns:
        -------
            str: JWT access token string
        """
        refresh = RefreshToken.for_user(obj)
        return str(refresh.access_token)

    def get_refresh(self, obj):
        """Generate JWT refresh token for the authenticated user.

        Args:
        ----
            obj (User): User instance to generate token for

        Returns:
        -------
            str: JWT refresh token string
        """
        refresh = RefreshToken.for_user(obj)
        return str(refresh)


class ChangeEmailSerializer(serializers.Serializer):
    """Serializer for changing user email.

    Handles the validation and processing of email change requests,
    requiring password verification and ensuring new email uniqueness.

    Attributes
    ----------
        new_email (EmailField): User's desired new email address
        password (CharField): User's password for verification
    """

    new_email = serializers.EmailField(
        required=True, help_text="New email address"
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text="Password for verification",
    )

    def validate_new_email(self, value):
        """Validate that the new email is unique and properly formatted.

        Args:
        ----
            value (str): The new email to validate

        Returns:
        -------
            str: The validated new email

        Raises:
        ------
            serializers.ValidationError: If email validation fails
        """
        value = value.lower()  # Normalize email to lowercase

        # Check if email is already in use
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                _("This email is already in use.")
            )

        return value


class ChangeMobileSerializer(serializers.Serializer):
    """Serializer for changing user mobile number.

    Handles the validation and processing of mobile number change requests,
    requiring password verification and ensuring new mobile uniqueness.

    Attributes
    ----------
        new_mobile (CharField): User's desired new mobile number
        password (CharField): User's password for verification
    """

    new_mobile = serializers.CharField(
        required=True, help_text="New mobile number"
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text="Password for verification",
    )

    def validate_new_mobile(self, value):
        """Validate that the new mobile number is unique and properly formatted.

        Args:
        ----
            value (str): The new mobile number to validate

        Returns:
        -------
            str: The validated new mobile number

        Raises:
        ------
            serializers.ValidationError: If mobile validation fails
        """
        # Check if mobile is already in use
        if User.objects.filter(mobile=value).exists():
            raise serializers.ValidationError(
                _("This mobile number is already in use.")
            )

        return value


class VerifyOTPSerializer(serializers.Serializer):
    """Serializer for verifying OTP.

    Handles validation and verification of OTP codes for various purposes.

    Attributes
    ----------
        identifier (CharField): Email or mobile number the OTP was sent to
        otp (CharField): The OTP code to verify
        purpose (CharField): Purpose of the OTP (registration, login, etc.)
    """

    identifier = serializers.CharField(
        required=True, help_text="Email or mobile number"
    )
    otp = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text="OTP code to verify",
    )
    purpose = serializers.ChoiceField(
        choices=OTP.PURPOSE_CHOICES,
        required=True,
        help_text="Purpose of the OTP",
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
            serializers.ValidationError: If neither email nor mobile is provided
        """
        if not data.get('email') and not data.get('mobile'):
            raise serializers.ValidationError(
                _("Either email or mobile must be provided.")
            )
        return data


class ResendOTPSerializer(serializers.Serializer):
    """Serializer for resending OTP.

    Handles validation and generation of new OTP codes.
    """

    email = serializers.EmailField(
        required=False, help_text="Email address to send OTP to"
    )
    mobile = serializers.CharField(
        required=False, help_text="Mobile number to send OTP to"
    )
    purpose = serializers.ChoiceField(
        choices=OTP.PURPOSE_CHOICES,
        required=True,
        help_text="Purpose of the OTP (REGISTER, LOGIN, etc.)",
    )

    def validate(self, data):
        """Validate that either email or mobile is provided and exists or not
        based on the purpose.

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
        purpose = data.get('purpose')

        if not email and not mobile:
            raise serializers.ValidationError(
                _("Either email or mobile must be provided.")
            )

        # For registration, we need to check if the identifier is already
        # registered
        if purpose == 'REGISTER':
            if email and User.objects.filter(email=email).exists():
                raise serializers.ValidationError(
                    _("This email is already registered.")
                )
            elif mobile and User.objects.filter(mobile=mobile).exists():
                raise serializers.ValidationError(
                    _("This mobile number is already registered.")
                )
        # For other purposes, we need to check if the identifier exists
        elif purpose in ['LOGIN', 'RESET_PASSWORD']:
            if email and not User.objects.filter(email=email).exists():
                raise serializers.ValidationError(
                    _("No account found with this email.")
                )
            elif mobile and not User.objects.filter(mobile=mobile).exists():
                raise serializers.ValidationError(
                    _("No account found with this mobile number.")
                )

        return data


class ResetPasswordConfirmSerializer(serializers.Serializer):
    """Serializer for confirming a password reset.

    Handles validation and processing of password reset confirmations.

    Attributes
    ----------
        identifier (CharField): Email or mobile number for which OTP was sent
        otp (CharField): The OTP code received
        new_password (CharField): New password to set
    """

    identifier = serializers.CharField(
        required=True, help_text="Email or mobile for which OTP was sent"
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
