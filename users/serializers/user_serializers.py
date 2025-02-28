import logging

from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import User

# Initialize logger
logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user registration, profile updates, and retrieving user
    details.

    This serializer handles the conversion between User model instances and JSON
    representation, with special handling for password hashing during user
    creation.

    Attributes
    ----------
        email (EmailField): Required unique email identifier for the user
        first_name (CharField): User's first name
        last_name (CharField): User's last name
        mobile (CharField): User's mobile number with validation
        password (CharField): User's password (write-only)
    """

    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'first_name',
            'last_name',
            'mobile',
            'password',
            'gender',
            'country_code',
            'dob',
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True},
        }

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
        return value.lower()  # Normalize email to lowercase

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
        # Set cr_by_self flag for users registering themselves
        validated_data['cr_by_self'] = True

        # Create user with hashed password
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()

        logger.info(f"New user registered: {user.email}")
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile information.

    This serializer handles updates to user profile data, excluding sensitive
    fields like password and email which require special workflows.

    Attributes
    ----------
        first_name (CharField): User's first name
        last_name (CharField): User's last name
        mobile (CharField): User's mobile number
        gender (CharField): User's gender selection
        dob (DateField): User's date of birth
        profile_pic (ImageField): User's profile picture
    """

    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
            'mobile',
            'country_code',
            'gender',
            'dob',
            'profile_pic',
        ]

    def validate_mobile(self, value):
        """Validate that the mobile number is unique if being changed.

        Args:
        ----
            value (str): The mobile number to validate

        Returns:
        -------
            str: The validated mobile number

        Raises:
        ------
            serializers.ValidationError: If mobile number is already in use
        """
        # Check if mobile number belongs to another user
        user = self.context.get('request').user
        if User.objects.exclude(id=user.id).filter(mobile=value).exists():
            raise serializers.ValidationError(
                _("This mobile number is already in use.")
            )
        return value

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
        logger.info(f"User profile updated: {instance.email}")
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

    Attributes
    ----------
        email (EmailField): User's email address
        password (CharField): User's password (write-only)
    """

    email = serializers.EmailField(
        required=True, help_text="Email address for login"
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text="Password for authentication",
    )

    def validate_email(self, value):
        """Normalize email to lowercase for case-insensitive login."""
        return value.lower()


class UserSerializerWithToken(UserSerializer):
    """Extended User Serializer that includes JWT access token.

    This serializer adds a token field to the standard user serializer
    for returning authentication tokens along with user data after
    successful authentication.

    Attributes
    ----------
        token (SerializerMethodField): JWT access token for authentication
    """

    token = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = UserSerializer.Meta.fields + ['token']

    def get_token(self, obj):
        """Generate JWT access token for the authenticated user.

        Args:
        ----
            obj (User): User instance to generate token for

        Returns:
        -------
            str: JWT access token string
        """
        token = RefreshToken.for_user(obj)
        return str(token.access_token)


# Swagger schema helpers for serializers
swagger_schema_fields = {
    'UserSerializer': {
        'type': openapi.TYPE_OBJECT,
        'properties': {
            'id': openapi.Schema(type=openapi.TYPE_INTEGER, read_only=True),
            'email': openapi.Schema(
                type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL
            ),
            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
            'mobile': openapi.Schema(type=openapi.TYPE_STRING),
            'password': openapi.Schema(
                type=openapi.TYPE_STRING, write_only=True
            ),
            'gender': openapi.Schema(type=openapi.TYPE_STRING, enum=['M', 'F']),
            'dob': openapi.Schema(
                type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE
            ),
        },
        'required': ['email', 'password', 'mobile'],
    }
}
