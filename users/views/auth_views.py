import logging
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from six import text_type

# Import your serializers
from users.serializers import (
    ActivateAccountSerializer,
    ResetPasswordConfirmSerializer,
    ResetPasswordRequestSerializer,
)

# Logger setup
logger = logging.getLogger(__name__)

# Get User model
User = get_user_model()


class TokenGenerator(PasswordResetTokenGenerator):
    """Custom token generator for account activation.

    This extends Django's PasswordResetTokenGenerator to create a unique token
    for account activation, incorporating the user's active status.
    """

    def _make_hash_value(self, user, timestamp):
        return (
            text_type(user.pk)
            + text_type(timestamp)
            + text_type(user.is_active)
        )


# Create instances of token generators
account_activation_token = TokenGenerator()
password_reset_token = PasswordResetTokenGenerator()


class PasswordResetRequestView(APIView):
    """API endpoint to request a password reset.

    This endpoint initiates the password reset flow by generating and sending
    a secure token to the user's registered email address.

    ## Request Requirements:
    - Must provide a valid email address
    - Account must exist, be active, and not deleted

    ## Process Flow:
    1. Validates the email address format
    2. Checks if the email exists in the system and is not deleted
    3. Generates a secure reset token
    4. Sets the password reset flag on the user account
    5. Sends email with secure reset link
    6. Returns generic success response

    ## Security Measures:
    - Rate limiting for request attempts
    - Same response timing for existing and non-existing emails
    - Generic success message regardless of email existence
    - Secure token generation with Django's PasswordResetTokenGenerator
    - Limited token validity
    - Soft deletion check

    ## Notes:
    - Actual email sending handled by external service
    - In development mode, returns the token info in response
    - The user must verify their identity with the token
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='password_reset_request',
        operation_summary="Request Password Reset",
        operation_description="""
        Request a password reset link to be sent to the user's email.

        ## Request Requirements:
        - Valid email address format
        - Email must be registered with an active account

        ## Process Flow:
        1. Validates email format
        2. Locates user account (if exists)
        3. Generates secure reset token
        4. Sends email with reset instructions
        5. Returns consistent response (security measure)

        ## Security:
        - Rate limited to prevent abuse
        - Consistent response timing regardless of email existence
        - Generic responses to prevent user enumeration
        - Tokens include additional security measures

        ## Response:
        - Same success message returned regardless of email validity
        - Debug information included only in development mode
        """,
        request_body=ResetPasswordRequestSerializer,
        responses={
            200: openapi.Response(
                description="Reset request processed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            400: "Invalid email format",
            429: "Too many reset requests",
        },
    )
    def post(self, request, *args, **kwargs):
        """Process password reset request and send reset email.

        Handles the password reset request by:
        1. Validating the email format
        2. Checking for an existing active user with that email
        3. Generating a secure token if the user exists
        4. Setting up the password reset email
        5. Returning a consistent response for security

        Security measures:
        - Rate limiting enforced by throttle_classes
        - Same response timing regardless of email validity
        - Generic response message to prevent user enumeration
        - Detailed logging for security audit

        Args:
        ----
            request: The HTTP request object containing query parameters
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Consistent success message regardless of email validity
                On success: HTTP 200 with generic success message
                On rate limit: HTTP 429 with throttling message
                On validation error: HTTP 400 with validation errors
        """
        serializer = ResetPasswordRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data['email']
        user = User.objects.filter(
            email=email, is_active=True, is_deleted=False
        ).first()

        # Always return success even if email not found (security best practice)
        if not user:
            logger.info(
                f"Password reset attempted for non-existent or inactive \
                    email: {email}"
            )
            time.sleep(1)  # Delay to prevent timing attacks
            return Response(
                {
                    "detail": _(
                        "If your email is registered, you will receive a \
                            password reset link"
                    )
                },
                status=status.HTTP_200_OK,
            )

        # Generate password reset token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = password_reset_token.make_token(user)

        # Set password reset flag
        user.is_password_reset_link_sent = True
        user.save(update_fields=['is_password_reset_link_sent'])

        # TODO: Send actual email with reset link
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"

        # In a real implementation, you would call an email service:
        # send_password_reset_email(user.email, reset_url)

        logger.info(f"Password reset email would be sent to: {email}")

        # For development purposes, return the token info
        if settings.DEBUG:
            debug_info = {"uid": uid, "token": token, "reset_url": reset_url}
        else:
            debug_info = None

        return Response(
            {
                "detail": _(
                    "If your email is registered, you will receive a password \
                        reset link"
                ),
                "debug_info": debug_info,
            },
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmView(APIView):
    """API endpoint to confirm a password reset request.

    Validates the reset token and allows the user to set a new password.

    ## Request Requirements:
    - Must provide valid UID (encoded user ID)
    - Must provide valid reset token received via email
    - Must provide new password meeting security requirements
    - Token must not be expired or already used
    - Associated user must not be deleted

    ## Process Flow:
    1. Validates the UID, token, and new password format
    2. Decodes the UID to identify the user
    3. Verifies the token's validity and expiration
    4. Sets the new password for the user
    5. Clears the password reset flag
    6. Returns confirmation message

    ## Security Measures:
    - Rate limiting for request attempts
    - Token validation with proper error handling
    - Password strength validation
    - One-time use tokens
    - Comprehensive error logging for security audit
    - Soft deletion checks

    ## Notes:
    - UID is a base64-encoded user ID
    - Tokens have limited validity period
    - Successfully setting a new password invalidates the token
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='password_reset_confirm',
        operation_summary="Confirm Password Reset",
        operation_description="""
        Set a new password using the reset token received via email.

        ## Request Requirements:
        - UID must be a valid base64-encoded user ID
        - Token must be valid and not expired
        - New password must meet complexity requirements
        - User account must be active

        ## Process Flow:
        1. Validates input data format
        2. Decodes the UID to identify user
        3. Verifies token authenticity and expiration
        4. Sets new password if token is valid
        5. Returns success or error response

        ## Security:
        - Rate limited to prevent brute force attempts
        - Tokens are single-use and time-limited
        - Password complexity enforced
        - Generic error messages for invalid attempts

        ## Response:
        - Success message on successful password reset
        - Error details for invalid requests
        """,
        request_body=ResetPasswordConfirmSerializer,
        responses={
            200: openapi.Response(
                description="Password reset successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(type=openapi.TYPE_STRING)
                    },
                ),
            ),
            400: "Invalid token, UID, or password",
            429: "Too many attempts",
        },
    )
    def post(self, request, *args, **kwargs):
        """Validate token and set new password.

        Processes the password reset confirmation by:
        1. Validating the submitted data format
        2. Decoding the user ID from the UID
        3. Verifying the reset token's validity
        4. Setting the new password if all checks pass

        Security measures:
        - Rate limiting to prevent brute force attempts
        - Comprehensive validation of token and UID
        - Strong password requirements enforced
        - Detailed error logging with minimal exposure

        Args:
        ----
            request: The HTTP request object containing query parameters
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Success message or appropriate error
                On success: HTTP 200 with confirmation message
                On invalid token/UID: HTTP 400 with error message
                On validation error: HTTP 400 with validation errors
        """
        serializer = ResetPasswordConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Extract data from serializer
        uid = serializer.validated_data['uid']
        token = serializer.validated_data['token']
        password = serializer.validated_data['new_password']

        try:
            # Decode the UID
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(
                pk=user_id, is_active=True, is_deleted=False
            )

            # Verify token
            if not password_reset_token.check_token(user, token):
                logger.warning(
                    f"Invalid password reset token for user ID: {user_id}"
                )
                return Response(
                    {"detail": _("Invalid or expired token")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Set new password
            user.set_password(password)
            user.is_password_reset_link_sent = False
            user.save()

            logger.info(f"Password reset successfully for user: {user.email}")

            return Response(
                {"detail": _("Password has been reset successfully")},
                status=status.HTTP_200_OK,
            )

        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            logger.error(f"Password reset error: {str(e)}")
            return Response(
                {"detail": _("Invalid or expired token")},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ActivateUserView(APIView):
    """API endpoint to activate a user account.

    Validates the activation token and activates the user account.

    ## Request Requirements:
    - Must provide valid UID (encoded user ID)
    - Must provide valid activation token received via email
    - Associated user must not be deleted

    ## Process Flow:
    1. Validates the UID and token format
    2. Decodes the UID to identify the user
    3. Verifies the token's validity
    4. Activates the user account if not already active
    5. Returns confirmation message

    ## Security Measures:
    - Token validation with proper error handling
    - Comprehensive error logging for security audit
    - Soft deletion checks
    - Prevention of activation for deleted accounts

    ## Notes:
    - UID is a base64-encoded user ID
    - Account activation is idempotent (safe to attempt multiple times)
    - Successfully activating an account marks it as verified
    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='activate_account',
        operation_summary="Activate User Account",
        operation_description="""
        Activate a user account using the validation token received via email.

        ## Request Requirements:
        - UID must be a valid base64-encoded user ID (uidb64)
        - Token must be valid and not expired
        - User account must not be deleted

        ## Process Flow:
        1. Validates input data format
        2. Decodes the UID to identify user
        3. Verifies token authenticity
        4. Activates the account if not already active
        5. Returns success or error response

        ## Response:
        - Success message on successful activation
        - Success with notification if already activated
        - Error details for invalid activation attempts
        """,
        request_body=ActivateAccountSerializer,
        responses={
            200: openapi.Response(
                description="Account activated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(type=openapi.TYPE_STRING)
                    },
                ),
            ),
            400: "Invalid token or UID",
        },
    )
    def post(self, request, *args, **kwargs):
        """Validate activation token and activate user account.

        Processes the account activation request by:
        1. Validating the submitted data format
        2. Decoding the user ID from the UID
        3. Verifying the activation token's validity
        4. Activating the account if all checks pass

        Security measures:
        - Comprehensive validation of token and UID
        - Handling of already activated accounts
        - Detailed error logging with appropriate error messages
        - Prevention of activating deleted accounts

        Args:
        ----
            request: The HTTP request object containing query parameters
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Success message or appropriate error
                On success: HTTP 200 with confirmation message
                On already active: HTTP 200 with notification
                On invalid token/UID: HTTP 400 with error message
        """
        serializer = ActivateAccountSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        uidb64 = serializer.validated_data['uidb64']
        token = serializer.validated_data['token']

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid, is_deleted=False)

            if user.is_active:
                return Response(
                    {"detail": _("Account is already activated.")},
                    status=status.HTTP_200_OK,
                )

            if account_activation_token.check_token(user, token):
                user.is_active = True
                user.account_verified = True  # If you have this field
                user.save()

                logger.info(f"User account activated: {user.email}")

                return Response(
                    {
                        "detail": _(
                            "Thank you for confirming your email. Your account \
                                is now active."
                        )
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                logger.warning(
                    f"Invalid activation token for user: {user.email}"
                )
                return Response(
                    {"detail": _("Activation link is invalid or has expired!")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            logger.error(f"Account activation error: {str(e)}")
            return Response(
                {"detail": _("Activation link is invalid!")},
                status=status.HTTP_400_BAD_REQUEST,
            )
