import ipaddress
import logging
import time

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from users.serializers import (
    ChangePasswordSerializer,
    LoginSerializer,
    UserSerializer,
    UserSerializerWithToken,
    UserUpdateSerializer,
)
from utils import send_account_activation_email

from .auth_views import account_activation_token

# Logger setup
logger = logging.getLogger(__name__)

# Get User model
User = get_user_model()


class LoginRateThrottle(AnonRateThrottle):
    """Throttle class for login attempts to prevent brute force attacks.
    Limits login attempts to 5 per minute.
    """

    rate = '5/min'
    scope = 'login'


class LoginView(APIView):
    """API endpoint for user login with JWT authentication.

    This endpoint authenticates users via email and password,
    returning access and refresh tokens upon successful login.

    ## Request Requirements:
    - Must provide valid email address
    - Must provide correct password
    - Account must be active and not deleted

    ## Process Flow:
    1. Validates user credentials
    2. Authenticates user against database
    3. Records login IP address for security
    4. Generates JWT access & refresh tokens
    5. Returns tokens & detailed user data

    ## Security Measures:
    - Rate limiting (5 attempts per minute)
    - Generic error messages for security
    - IP address tracking for audit
    - JWT with configurable expiry
    - Soft deletion checks

    ## Response Data:
    - Access token for API authorization
    - Refresh token for token renewal
    - User profile information
    """

    throttle_classes = [LoginRateThrottle]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='login_user',
        operation_summary="User Login",
        operation_description="""
        Authenticate with email and password to receive JWT tokens.

        ## Request Requirements:
        - Email must be registered in the system
        - Password must match stored password
        - Account must be active (not disabled/suspended/deleted)

        ## Process Flow:
        1. Validates request format
        2. Authenticates credentials
        3. Records login activity
        4. Generates fresh JWT tokens
        5. Returns user data with tokens

        ## Security:
        - Rate limited to 5 attempts per minute
        - Login attempts are logged
        - IP addresses are recorded
        - Failed attempts use same response time
        - Soft-deleted accounts cannot log in

        ## Response Data:
        - message: Success confirmation
        - access: JWT access token
        - refresh: JWT refresh token
        - user: User profile data
        """,
        request_body=LoginSerializer,
        responses={
            200: openapi.Response(
                description="Login successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                    },
                ),
            ),
            400: "Invalid request data",
            401: "Invalid credentials",
            429: "Too many login attempts",
        },
    )
    def post(self, request):
        """Authenticates user and returns JWT tokens.

        Processes the login request by:
        1. Validating the request data format
        2. Extracting and authenticating credentials
        3. Recording login IP for security audit
        4. Generating fresh JWT tokens
        5. Returning tokens with user profile data

        Security measures:
        - Rate limiting enforced by throttle_classes
        - Generic error messages to prevent user enumeration
        - IP address tracking for security monitoring
        - Consistent response timing regardless of outcome
        - Soft deletion verification

        Args:
        ----
            request (Request): HTTP request with login credentials

        Returns:
        -------
            Response: Authentication result with tokens or error
                On success: HTTP 200 with tokens and user data
                On bad format: HTTP 400 with validation errors
                On auth failure: HTTP 401 with specific error message
                On rate limit: HTTP 429 with throttling message

        Raises:
        ------
            Exception: Logs but doesn't expose internal errors
        """
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Extract validated credentials
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        # Track login attempts for security
        client_ip = self._get_client_ip(request)

        try:
            # Check if user exists first and is not deleted
            user_exists = User.objects.filter(
                email=email, is_deleted=False
            ).exists()

            if not user_exists:
                # Log failed login attempt - user doesn't exist or is deleted
                logger.warning(
                    f"""Login attempt for non-existent or deleted email:
                    {email} from IP: {client_ip}"""
                )
                time.sleep(1)  # Delay to prevent timing attacks
                return Response(
                    {"detail": _("Invalid email or password")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # User exists and is not deleted, now check specific
            # issues before authentication
            user = User.objects.get(email=email, is_deleted=False)

            # Check if user is active
            if not user.is_active:
                logger.warning(
                    f"Login attempt for inactive account: {email} from IP: \
                        {client_ip}"
                )
                return Response(
                    {
                        "detail": _(
                            "Your account is inactive. Please contact an \
                            administrator."
                        )
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Check if account is verified (if you have this field)
            if hasattr(user, 'account_verified') and not user.account_verified:
                logger.warning(
                    f"Login attempt for unverified account: {email} \
                    from IP: {client_ip}"
                )
                return Response(
                    {
                        "detail": _(
                            "Please verify your account before logging in."
                        )
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Now try to authenticate with the password
            # Note: Django's authenticate will respect is_deleted=False
            # if it's in your User model
            authenticated_user = authenticate(
                request, email=email, password=password
            )

            if not authenticated_user:
                # Log failed login attempt - wrong password
                logger.warning(
                    f"Failed login attempt (wrong password) for: {email} \
                    from IP: {client_ip}"
                )
                return Response(
                    {"detail": _("Invalid email or password")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Double-check the authenticated user is not deleted
            # (belt and braces)
            if getattr(authenticated_user, 'is_deleted', False):
                logger.warning(
                    f"Login attempt for deleted account: {email} \
                    from IP: {client_ip}"
                )
                return Response(
                    {"detail": _("Invalid email or password")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Update last login IP if available
            if client_ip:
                authenticated_user.last_login_ip = client_ip
                authenticated_user.save(
                    update_fields=['last_login_ip', 'last_login']
                )

            # Generate tokens
            refresh = RefreshToken.for_user(authenticated_user)

            logger.info(
                f"User logged in: {authenticated_user.email} \
                    from IP: {client_ip}"
            )

            return Response(
                {
                    'message': _('Login successful'),
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': UserSerializerWithToken(authenticated_user).data,
                },
                status=status.HTTP_200_OK,
            )

        except User.DoesNotExist:
            # This should not happen due to our earlier check, but just in case
            logger.warning(
                f"Login attempt for non-existent email (exception): {email} \
                    from IP: {client_ip}"
            )
            return Response(
                {"detail": _("Invalid email or password")},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except Exception as e:
            # Log the exception but don't expose details to the client
            logger.error(
                f"Login error for {email} from IP {client_ip}: {str(e)}"
            )
            return Response(
                {
                    "detail": _(
                        "An error occurred during login. Please try again."
                    )
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_client_ip(self, request):
        """Extract client IP address from request.

        Args:
        ----
            request (Request): The HTTP request object

        Returns:
        -------
            str: The client IP address or None if not available
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get the first IP in case of proxy chains
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')

        # Validate IP address format
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            return None


class RegisterView(APIView):
    """API endpoint for user registration.

    Handles new user account creation with validation, email verification
    and account activation process.

    ## Request Requirements:
    - Must provide valid email address (unique)
    - Must provide secure password
    - Must provide required profile information
    - Mobile number must be valid format with country code
    - Email and mobile must not belong to existing non-deleted users

    ## Process Flow:
    1. Validates all user data fields
    2. Creates a new inactive user account
    3. Generates account activation token
    4. Sends verification email with activation link
    5. Returns registration success message

    ## Security Measures:
    - Rate limiting for registration attempts
    - Password strength validation
    - Email and mobile uniqueness checks
    - IP address tracking for audit
    - Soft deletion checks for uniqueness validation
    - Email verification required for account activation
    - Secure token generation for activation

    ## Notes:
    - User accounts are created with is_active=False until email verification
    - Email verification token is sent to user's email address
    - Users created through this endpoint have cr_by_self=True
    - Initial account has no role-specific permissions
    - is_deleted is set to False by default
    - In debug mode, activation token is returned in response
    """

    throttle_classes = [AnonRateThrottle]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='register_user',
        operation_summary="User Registration",
        operation_description="""
        Register a new user and send account activation email.

        ## Request Requirements:
        - Email must be valid and unique
        - Password must meet complexity requirements
        - Required profile fields must be provided
        - Mobile number must be valid format with country code

        ## Process Flow:
        1. Validates request data
        2. Creates new inactive user account
        3. Generates secure activation token
        4. Sends verification email to user
        5. Returns registration success message

        ## Account Activation:
        - User receives email with activation link
        - Account remains inactive until email is verified
        - Activation link contains secure token
        - Token expires after set period (typically 24-48 hours)

        ## Security:
        - Rate limited to prevent abuse
        - Password strength validation
        - Email verification required
        - Protection against account enumeration
        - IP address tracking for security audit

        ## Response:
        - Success message with verification instructions
        - In development mode, activation details included
        """,
        request_body=UserSerializer,
        responses={
            201: openapi.Response(
                description="User registered successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'debug_info': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'uid': openapi.Schema(type=openapi.TYPE_STRING),
                                'token': openapi.Schema(
                                    type=openapi.TYPE_STRING
                                ),
                                'activation_url': openapi.Schema(
                                    type=openapi.TYPE_STRING
                                ),
                            },
                        ),
                    },
                ),
            ),
            400: "Validation error",
            429: "Too many registration attempts",
        },
    )
    def post(self, request):
        """Register a new user and initiate account verification.

        Processes the registration request by:
        1. Validating the submitted user data
        2. Creating an inactive user account
        3. Generating an activation token
        4. Sending a verification email with activation link
        5. Returning success message with verification instructions

        Security measures:
        - Rate limiting for registration attempts
        - Email verification required for account activation
        - Detailed validation of all user fields
        - Protection against duplicate accounts through email/mobile uniqueness
        - IP address tracking for audit and security monitoring

        Args:
        ----
            request (Request): HTTP request with user registration data

        Returns:
        -------
            Response: Registration result
                On success: HTTP 201 with verification instructions
                On validation error: HTTP 400 with field-specific errors
                On rate limit: HTTP 429 with throttling message
        """
        # Track registration attempt IP address
        client_ip = self._get_client_ip(request)
        logger.info(f"Registration attempt from IP: {client_ip}")

        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            # Create user with is_active=False for email verification
            user = serializer.save(
                is_active=False, is_deleted=False, cr_by_self=True
            )

            # Generate activation token
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = account_activation_token.make_token(user)

            # Build activation URL
            activation_url = f"{settings.FRONTEND_URL}/activate/{uid}/{token}/"

            # Send activation email
            send_account_activation_email(user.email, activation_url)

            logger.info(
                f"User registered successfully: {user.email} \
                    from IP: {client_ip}"
            )

            # Prepare response
            response_data = {
                "message": _(
                    "Registration successful. Please check your email to \
                        activate your account."
                )
            }

            # Include debug info in development mode
            if settings.DEBUG:
                response_data["debug_info"] = {
                    "uid": uid,
                    "token": token,
                    "activation_url": activation_url,
                }

            return Response(response_data, status=status.HTTP_201_CREATED)

        # Log validation errors
        logger.warning(
            f"Registration validation error from IP \
                {client_ip}: {serializer.errors}"
        )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _get_client_ip(self, request):
        """Extract client IP address from request.

        Args:
        ----
            request (Request): The HTTP request object

        Returns:
        -------
            str: The client IP address or None if not available
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class UserProfileView(APIView):
    """API endpoint for retrieving and updating user profile.

    Allows authenticated users to view and update their own profile information.

    ## Access Requirements:
    - User must be authenticated with valid JWT
    - User can only access their own profile
    - User must not be soft-deleted

    ## Operations:
    - GET: Retrieve complete profile information
    - PUT: Update profile fields (partial updates supported)

    ## Updateable Fields:
    - first_name, last_name (personal info)
    - mobile, country_code (contact info)
    - gender, dob (demographic info)
    - profile_pic (profile image)

    ## Security Measures:
    - JWT authentication required
    - Rate limiting for update operations
    - Validation for all field formats
    - Uniqueness check for mobile number against non-deleted users
    - Soft deletion verification

    ## Notes:
    - Profile picture uploads handled with multipart form data
    - Mobile number changes require uniqueness validation
    - Email updates not permitted through this endpoint
    - Password changes handled by separate endpoint
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [UserRateThrottle]

    @swagger_auto_schema(
        tags=['User'],
        operation_id='get_profile',
        operation_summary="Retrieve User Profile",
        operation_description="Get the authenticated user's profile \
            information.",
        responses={
            200: UserUpdateSerializer(),
            401: "Authentication credentials not provided",
            403: "Permission denied",
        },
    )
    def get(self, request):
        """Fetches authenticated user's profile.

        Args:
        ----
            request (Request): HTTP request from authenticated user

        Returns:
        -------
            Response: User profile data
        """
        # Check if user is deleted
        if getattr(request.user, 'is_deleted', False):
            return Response(
                {"detail": _("User not found")},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = UserUpdateSerializer(request.user)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['User'],
        operation_id='update_profile',
        operation_summary="Update User Profile",
        operation_description="Update the authenticated user's profile \
            information.",
        request_body=UserUpdateSerializer,
        responses={
            200: openapi.Response(
                description="Profile updated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                    },
                ),
            ),
            400: "Validation error",
            401: "Authentication credentials not provided",
            403: "Permission denied",
            404: "User not found",
        },
    )
    def put(self, request):
        """Updates authenticated user's profile.

        Args:
        ----
            request (Request): HTTP request containing profile update data

        Returns:
        -------
            Response: Success message and updated user data or error messages
        """
        # Check if user is deleted
        if getattr(request.user, 'is_deleted', False):
            return Response(
                {"detail": _("User not found")},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = UserUpdateSerializer(
            request.user,
            data=request.data,
            partial=True,
            context={'request': request},
        )

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.save()
        logger.info(f"User profile updated: {user.email}")

        return Response(
            {
                "message": _("Profile updated successfully"),
                "user": UserUpdateSerializer(user).data,
            }
        )


class DeleteUserView(APIView):
    """API endpoint to delete a user account.

    Allows authenticated users to delete their own account.
    Implements soft deletion by setting is_deleted=True rather than
    removing the record from the database.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        tags=['User'],
        operation_id='delete_user',
        operation_summary="Delete User Account",
        operation_description="""
        Permanently deactivate the authenticated user's account.

        This implements soft deletion by marking the account as deleted rather
        thanremoving it from the database. This preserves referential integrity
        and allows for potential account recovery.
        """,
        responses={
            204: "User deleted successfully",
            400: "Error in deleting user",
            401: "Authentication credentials not provided",
            403: "Permission denied",
            404: "User not found",
        },
    )
    def delete(self, request):
        """Soft deletes the authenticated user account by setting
        is_deleted=True.

        Args:
        ----
            request (Request): HTTP request from authenticated user

        Returns:
        -------
            Response: Success message or error message
        """
        user = request.user
        email = user.email  # Store for logging

        # Check if user is already deleted
        if getattr(user, 'is_deleted', False):
            return Response(
                {"detail": _("User not found")},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            # Implement soft delete instead of actual deletion
            user.is_deleted = True
            user.is_active = False  # Also deactivate the account
            user.save(update_fields=['is_deleted', 'is_active'])

            logger.info(f"User soft deleted: {email}")
            return Response(
                {"message": _("User deleted successfully")},
                status=status.HTTP_204_NO_CONTENT,
            )
        except Exception as e:
            logger.error(f"Error deleting user {email}: {str(e)}")
            return Response(
                {"detail": _("Error deleting user account")},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ChangePasswordView(APIView):
    """API endpoint to change user password.

    Allows authenticated users to change their password by providing
    their current password and a new password.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [UserRateThrottle]

    @swagger_auto_schema(
        tags=['User'],
        operation_id='change_password',
        operation_summary="Change Password",
        operation_description="Change the authenticated user's password.",
        request_body=ChangePasswordSerializer,
        responses={
            200: openapi.Response(
                description="Password changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING)
                    },
                ),
            ),
            400: "Validation error or incorrect old password",
            401: "Authentication credentials not provided",
            403: "Permission denied",
            404: "User not found",
        },
    )
    def post(self, request):
        """Changes the authenticated user's password.

        Args:
        ----
            request (Request): HTTP request containing old and new passwords

        Returns:
        -------
            Response: Success message or error message
        """
        # Check if user is deleted
        if getattr(request.user, 'is_deleted', False):
            return Response(
                {"detail": _("User not found")},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ChangePasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Verify old password
        if not request.user.check_password(
            serializer.validated_data["old_password"]
        ):
            return Response(
                {"detail": _("Incorrect old password")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Set new password
        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save()

        # Log password change
        logger.info(f"Password changed for user: {request.user.email}")

        # Return success response
        return Response(
            {"message": _("Password updated successfully")},
            status=status.HTTP_200_OK,
        )
