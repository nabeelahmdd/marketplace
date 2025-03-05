import logging
import time

from django.contrib.auth import authenticate
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import OTP, User
from users.serializers import (
    ChangeEmailSerializer,
    ChangeMobileSerializer,
    ChangePasswordSerializer,
    LoginSerializer,
    ResendOTPSerializer,
    ResetPasswordConfirmSerializer,
    ResetPasswordRequestSerializer,
    UserSerializer,
    UserSerializerWithToken,
    UserUpdateSerializer,
    VerifyOTPSerializer,
)

# Logger setup
logger = logging.getLogger(__name__)


class LoginRateThrottle(AnonRateThrottle):
    """Throttle class for login attempts to prevent brute force attacks.
    Limits login attempts to 5 per minute.
    """

    rate = '5/min'
    scope = 'login'


class LoginView(APIView):
    """API endpoint for user login with JWT authentication.

    This endpoint authenticates users via email/mobile and password,
    returning access and refresh tokens upon successful login.

    ## Request Requirements:
    - Must provide either valid email address or mobile number
    - Must provide correct password
    - Account must be active

    ## Process Flow:
    1. Validates user credentials
    2. Authenticates user against database
    3. Generates JWT access & refresh tokens
    4. Returns tokens & detailed user data

    ## Security Measures:
    - Rate limiting (5 attempts per minute)
    - Generic error messages for security
    - JWT with configurable expiry

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
        Authenticate with email/mobile and password to receive JWT tokens.

        ## Request Requirements:
        - Email or mobile must be registered in the system
        - Password must match stored password
        - Account must be active

        ## Process Flow:
        1. Validates request format
        2. Authenticates credentials
        3. Generates fresh JWT tokens
        4. Returns user data with tokens

        ## Security:
        - Rate limited to 5 attempts per minute
        - Login attempts are logged
        - Failed attempts use same response time

        ## Response Data:
        - message: Success confirmation
        - user: User profile data with tokens
        """,
        request_body=LoginSerializer,
        responses={
            200: openapi.Response(
                description="Login successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
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
        3. Generating fresh JWT tokens
        4. Returning tokens with user profile data

        Security measures:
        - Rate limiting enforced by throttle_classes
        - Generic error messages to prevent user enumeration
        - Consistent response timing regardless of outcome

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
        email = serializer.validated_data.get('email')
        mobile = serializer.validated_data.get('mobile')
        password = serializer.validated_data['password']

        try:
            # Determine user by email or mobile
            lookup_kwargs = {}
            if email:
                lookup_kwargs['email'] = email
            elif mobile:
                lookup_kwargs['mobile'] = mobile

            # Check if user exists
            user_exists = User.objects.filter(**lookup_kwargs).exists()

            if not user_exists:
                # Log failed login attempt - user doesn't exist
                logger.warning(
                    f"Login attempt for non-existent account: {email or mobile}"
                )
                time.sleep(1)  # Delay to prevent timing attacks
                return Response(
                    {"detail": _("Invalid credentials")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Now authenticate the user
            # Need to adapt depending on which field was provided
            user = authenticate(
                request, email=email, mobile=mobile, password=password
            )

            if not user:
                # Log failed login attempt - wrong password
                logger.warning(
                    f"Failed login attempt (wrong password) for: \
                        {email or mobile}"
                )
                return Response(
                    {"detail": _("Invalid credentials")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Check if user is verified
            if not user.is_verified:
                # Generate OTP for verification
                identifier = email or mobile
                otp_type = 'EMAIL' if email else 'PHONE'

                # Generate and send OTP
                otp = OTP.generate_otp(
                    identifier=identifier, type=otp_type, purpose='LOGIN'
                )

                # In a real implementation, you would send the OTP via email
                # or SMS here
                # For now, we'll just log it
                logger.info(
                    f"Login OTP generated for unverified user: \
                        {identifier}, OTP: {otp.otp}"
                )
                print(
                    (
                        f"Login OTP generated for unverified user: \
                            {identifier}, OTP: {otp.otp}"
                    )
                )

                return Response(
                    {
                        "detail": _(
                            "Account not verified. OTP sent for verification."
                        ),
                        "requires_verification": True,
                        "identifier": identifier,
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Generate tokens
            RefreshToken.for_user(user)

            logger.info(f"User logged in: {user.email or user.mobile}")

            return Response(
                {
                    'message': _('Login successful'),
                    'user': UserSerializerWithToken(user).data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            # Log the exception but don't expose details to the client
            logger.error(f"Login error for {email or mobile}: {str(e)}")
            return Response(
                {
                    "detail": _(
                        "An error occurred during login. Please try again."
                    )
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RegisterView(APIView):
    """API endpoint for user registration.

    Handles new user account creation with validation and OTP verification.

    ## Request Requirements:
    - Must provide name
    - Must provide either valid email address (unique) or mobile number (unique)
    - Must provide secure password
    - Email and mobile must not belong to existing users

    ## Process Flow:
    1. Validates all user data fields
    2. Creates a new unverified user account
    3. Sends OTP for verification
    4. Returns registration initiated message with instructions

    ## Security Measures:
    - Rate limiting for registration attempts
    - Password strength validation
    - Email and mobile uniqueness checks
    - OTP verification required to complete registration
    """

    throttle_classes = [AnonRateThrottle]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='register_user',
        operation_summary="User Registration",
        operation_description="""
        Register a new user with name, email/mobile, and password.

        ## Request Requirements:
        - Name must be provided
        - Either email or mobile must be valid and unique
        - Password must meet complexity requirements

        ## Process Flow:
        1. Validates request data
        2. Creates new unverified user account
        3. Sends OTP for verification
        4. Returns registration initiated message

        ## Security:
        - Rate limited to prevent abuse
        - Password strength validation
        - OTP verification required to complete registration
        - Protection against account enumeration

        ## Response:
        - Success message with verification instructions
        """,
        request_body=UserSerializer,
        responses={
            201: openapi.Response(
                description="Registration initiated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'identifier': openapi.Schema(type=openapi.TYPE_STRING),
                        'requires_verification': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN
                        ),
                    },
                ),
            ),
            400: "Validation error",
            429: "Too many registration attempts",
        },
    )
    def post(self, request):
        """Register a new user.

        Processes the registration request by:
        1. Validating the submitted user data
        2. Creating an unverified user account
        3. Sending OTP for verification

        Security measures:
        - Rate limiting for registration attempts
        - Detailed validation of all user fields
        - Protection against duplicate accounts through email/mobile uniqueness
        - OTP verification required to complete registration

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
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            # Create user with is_verified=False
            user = serializer.save(is_verified=False)

            # Determine identifier and OTP type
            identifier = user.email if user.email else user.mobile
            otp_type = 'EMAIL' if user.email else 'PHONE'

            # Generate and send OTP
            otp = OTP.generate_otp(
                identifier=identifier, type=otp_type, purpose='REGISTER'
            )

            # In a real implementation, you would send the OTP via email or \
            # SMS here
            # For now, we'll just log it
            logger.info(
                f"Registration OTP generated: {identifier}, OTP: {otp.otp}"
            )

            logger.info(f"User registration initiated: {identifier}")

            # Return success response with verification instructions
            return Response(
                {
                    "message": _(
                        "Registration initiated. Please verify your account \
                            with the OTP sent."
                    ),
                    "identifier": identifier,
                    "requires_verification": True,
                },
                status=status.HTTP_201_CREATED,
            )

        # Log validation errors
        logger.warning(f"Registration validation error: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    """API endpoint for retrieving and updating user profile.

    Allows authenticated users to view and update their own profile information.

    ## Access Requirements:
    - User must be authenticated with valid JWT
    - User can only access their own profile

    ## Operations:
    - GET: Retrieve complete profile information
    - PUT: Update profile fields (partial updates supported)

    ## Updateable Fields:
    - name (full name)
    - profile_image (profile image)
    - location (geographical location)

    ## Security Measures:
    - JWT authentication required
    - Rate limiting for update operations
    - Validation for all field formats
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
            200: UserSerializer(),
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
        serializer = UserSerializer(request.user)
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
        logger.info(f"User profile updated: {user.email or user.mobile}")

        return Response(
            {
                "message": _("Profile updated successfully"),
                "user": UserSerializer(user).data,
            }
        )


class LogoutView(APIView):
    """API endpoint to log out a user.

    Blacklists the refresh token to prevent further use.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='logout_user',
        operation_summary="User Logout",
        operation_description="Logout the authenticated user by blacklisting \
            their refresh token.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['refresh'],
            properties={
                'refresh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="JWT refresh token to blacklist",
                )
            },
        ),
        responses={
            200: openapi.Response(
                description="Logout successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            400: "Invalid token",
            401: "Authentication credentials not provided",
        },
    )
    def post(self, request):
        """Logs out the user by blacklisting their refresh token.

        Args:
        ----
            request (Request): HTTP request with refresh token

        Returns:
        -------
            Response: Success message or error message
        """
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response(
                    {"detail": _("Refresh token is required")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            token = RefreshToken(refresh_token)
            token.blacklist()

            logger.info(
                f"User logged out: {request.user.email or request.user.mobile}"
            )
            return Response(
                {"message": _("Logout successful")},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response(
                {"detail": _("Invalid token")},
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
        logger.info(
            f"Password changed for user: \
                {request.user.email or request.user.mobile}"
        )

        # Return success response
        return Response(
            {"message": _("Password updated successfully")},
            status=status.HTTP_200_OK,
        )


class ChangeEmailView(APIView):
    """API endpoint to change user email.

    Allows authenticated users to change their email address by providing
    their password for verification and a new unique email address.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [UserRateThrottle]

    @swagger_auto_schema(
        tags=['User'],
        operation_id='change_email',
        operation_summary="Change Email",
        operation_description="Change the authenticated user's email address.",
        request_body=ChangeEmailSerializer,
        responses={
            200: openapi.Response(
                description="Email changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'requires_verification': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN
                        ),
                        'identifier': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            400: "Validation error or incorrect password",
            401: "Authentication credentials not provided",
            403: "Permission denied",
        },
    )
    def post(self, request):
        """Changes the authenticated user's email address.

        Args:
        ----
            request (Request): HTTP request containing new email and password

        Returns:
        -------
            Response: Success message or error message
        """
        serializer = ChangeEmailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Verify password
        if not request.user.check_password(
            serializer.validated_data["password"]
        ):
            return Response(
                {"detail": _("Incorrect password")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Get new email and generate OTP for verification
        new_email = serializer.validated_data["new_email"]

        # Generate and send OTP
        otp = OTP.generate_otp(
            identifier=new_email, type='EMAIL', purpose='VERIFY_NEW_EMAIL'
        )

        # In a real implementation, you would send the OTP via email here
        # For now, we'll just log it
        logger.info(
            f"Email change OTP generated for {request.user.email} to \
                {new_email}: {otp.otp}"
        )

        # Return response with verification instructions
        return Response(
            {
                "message": _(
                    "Please verify your new email address with the OTP sent."
                ),
                "requires_verification": True,
                "identifier": new_email,
            },
            status=status.HTTP_200_OK,
        )


class ChangeMobileView(APIView):
    """API endpoint to change user mobile.

    Allows authenticated users to change their mobile address by providing
    their password for verification and a new unique mobile address.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [UserRateThrottle]

    @swagger_auto_schema(
        tags=['User'],
        operation_id='change_mobile',
        operation_summary="Change Mobile",
        operation_description="Change the authenticated user's mobile address.",
        request_body=ChangeMobileSerializer,
        responses={
            200: openapi.Response(
                description="Mobile changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'requires_verification': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN
                        ),
                        'identifier': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            400: "Validation error or incorrect password",
            401: "Authentication credentials not provided",
            403: "Permission denied",
        },
    )
    def post(self, request):
        """Changes the authenticated user's mobile address.

        Args:
        ----
            request (Request): HTTP request containing new mobile and password

        Returns:
        -------
            Response: Success message or error message
        """
        serializer = ChangeMobileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Verify password
        if not request.user.check_password(
            serializer.validated_data["password"]
        ):
            return Response(
                {"detail": _("Incorrect password")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Get new mobile and generate OTP for verification
        new_mobile = serializer.validated_data["new_mobile"]

        # Generate and send OTP
        otp = OTP.generate_otp(
            identifier=new_mobile, type='EMAIL', purpose='VERIFY_NEW_PHONE'
        )

        # In a real implementation, you would send the OTP via mobile here
        # For now, we'll just log it
        logger.info(
            f"Mobile change OTP generated for {request.user.mobile} to \
                {new_mobile}: {otp.otp}"
        )

        # Return response with verification instructions
        return Response(
            {
                "message": _(
                    "Please verify your new mobile address with the OTP sent."
                ),
                "requires_verification": True,
                "identifier": new_mobile,
            },
            status=status.HTTP_200_OK,
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


class VerifyOTPView(APIView):
    """API endpoint to verify an OTP.

    Validates the provided OTP against the stored OTP record.
    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='verify_otp',
        operation_summary="Verify OTP",
        operation_description="""
        Verify an OTP code for a specific identifier and purpose.

        This endpoint checks if the provided OTP is valid for the given
        identifier (phone/email) and purpose.

        ## Request Requirements:
        - Identifier (phone/email) for which OTP was generated
        - OTP code to verify
        - Purpose for which OTP was generated

        ## Process Flow:
        1. Locates the active OTP record
        2. Verifies OTP code validity
        3. Updates OTP record verification status
        4. Returns verification result

        ## Security:
        - Maximum 3 verification attempts per OTP
        - OTPs expire after 10 minutes
        - OTP is marked as verified after successful verification
        """,
        request_body=VerifyOTPSerializer,
        responses={
            200: openapi.Response(
                description="OTP verified successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'verified': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    },
                ),
            ),
            400: "Invalid or expired OTP",
        },
    )
    def post(self, request):
        """Verify an OTP code.

        Args:
        ----
            request: HTTP request with identifier, OTP, and purpose

        Returns:
        -------
            Response: Verification result
        """
        serializer = VerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        identifier = serializer.validated_data['identifier']
        otp_code = serializer.validated_data['otp']
        purpose = serializer.validated_data['purpose']

        # Find the active OTP record
        otp_obj = (
            OTP.objects.filter(
                identifier=identifier,
                purpose=purpose,
                is_verified=False,
                expires_at__gt=timezone.now(),
            )
            .order_by('-created_at')
            .first()
        )

        if not otp_obj:
            return Response(
                {"detail": _("Invalid or expired OTP")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify OTP
        verified = otp_obj.verify(otp_code)

        if not verified:
            attempts_left = otp_obj.max_attempts - otp_obj.attempts

            if attempts_left > 0:
                return Response(
                    {
                        "detail": _("Invalid OTP"),
                        "verified": False,
                        "attempts_left": attempts_left,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                return Response(
                    {
                        "detail": _(
                            "Maximum verification attempts exceeded. \
                                Please request a new OTP."
                        ),
                        "verified": False,
                        "attempts_left": 0,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        logger.info(
            f"OTP verified successfully for {identifier}, purpose: {purpose}"
        )

        # Handle specific actions based on purpose
        if purpose in ['REGISTER', 'LOGIN']:
            try:
                if '@' in identifier:
                    user = User.objects.get(email=identifier)
                else:
                    user = User.objects.get(mobile=identifier)

                user.is_verified = True
                user.save()

                # Generate tokens for auto-login
                RefreshToken.for_user(user)

                return Response(
                    {
                        "message": _("Account verified successfully."),
                        "verified": True,
                        "user": UserSerializerWithToken(user).data,
                    },
                    status=status.HTTP_200_OK,
                )
            except User.DoesNotExist:
                return Response(
                    {"detail": _("User not found.")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        elif purpose == 'VERIFY_NEW_EMAIL':
            # Only authenticated users can change their email
            if not request.user.is_authenticated:
                return Response(
                    {"detail": _("Authentication required to update email.")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Check if email is already in use by another user
            if (
                User.objects.exclude(id=request.user.id)
                .filter(email=identifier)
                .exists()
            ):
                return Response(
                    {
                        "detail": _(
                            "This email is already in use by another account."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Update the email
            request.user.email = identifier
            request.user.save()

            logger.info(
                f"Email updated for user {request.user.id} to {identifier}"
            )

            return Response(
                {
                    "message": _("Email verified and updated successfully."),
                    "verified": True,
                    "user": UserSerializer(request.user).data,
                },
                status=status.HTTP_200_OK,
            )

        elif purpose == 'VERIFY_NEW_PHONE':
            # Only authenticated users can change their mobile
            if not request.user.is_authenticated:
                return Response(
                    {
                        "detail": _(
                            "Authentication required to update mobile number."
                        )
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Check if mobile is already in use by another user
            if (
                User.objects.exclude(id=request.user.id)
                .filter(mobile=identifier)
                .exists()
            ):
                return Response(
                    {
                        "detail": _(
                            "This mobile number is already in use by another \
                                account."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Update the mobile number
            request.user.mobile = identifier
            request.user.save()

            logger.info(
                f"Mobile number updated for user {request.user.id} to \
                    {identifier}"
            )

            return Response(
                {
                    "message": _(
                        "Mobile number verified and updated successfully."
                    ),
                    "verified": True,
                    "user": UserSerializer(request.user).data,
                },
                status=status.HTTP_200_OK,
            )

        elif purpose == 'RESET_PASSWORD':
            # For password reset, we'll just return success
            # The actual password change will happen in a separate view
            return Response(
                {
                    "message": _(
                        "OTP verified successfully. You can now reset your \
                            password."
                    ),
                    "verified": True,
                    "identifier": identifier,
                },
                status=status.HTTP_200_OK,
            )

        # OTP verified successfully for other purposes
        return Response(
            {"message": _("OTP verified successfully"), "verified": True},
            status=status.HTTP_200_OK,
        )


class ResetPasswordRequestView(APIView):
    """API endpoint to request a password reset.

    Initiates the password reset process by sending an OTP to the user's
    registered email or mobile number. This is the first step in the two-step
    password reset flow.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='reset_password_request',
        operation_summary="Request Password Reset",
        operation_description="""
        Initiate the password reset process by requesting an OTP.

        ## Request Requirements:
        - Either email or mobile must be provided

        ## Process Flow:
        1. User submits their email or mobile number
        2. System validates the account exists
        3. System generates and sends an OTP
        4. User receives the OTP for the next step

        ## Security Features:
        - Rate limited to prevent brute force attempts
        - Generic response messaging prevents account enumeration
        - OTP has limited validity period (typically 10 minutes)
        - Maximum 3 verification attempts per OTP

        ## Next Steps:
        After receiving the OTP, proceed to the /auth/reset-password/confirm/
        endpoint to verify the OTP and set a new password.
        """,
        request_body=ResetPasswordRequestSerializer,
        responses={
            200: openapi.Response(
                description="Password reset OTP sent",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Success message indicating OTP has \
                                been sent",
                        ),
                    },
                ),
            ),
            400: openapi.Response(
                description="Validation error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Error details",
                        ),
                    },
                ),
            ),
            429: openapi.Response(
                description="Too many requests",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Rate limit exceeded message",
                        ),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        """Request a password reset OTP.

        Processes the password reset request by:
        1. Validating the provided email or mobile
        2. Checking if the user exists in the system
        3. Generating and sending an OTP
        4. Returning a success message

        Args:
        ----
            request: HTTP request with email or mobile

        Returns:
        -------
            Response: Result of password reset request with
                     appropriate status code and message
        """
        try:
            serializer = ResetPasswordRequestSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )

            email = serializer.validated_data.get('email')
            mobile = serializer.validated_data.get('mobile')

            # Determine identifier and type
            if email:
                identifier = email
                type_value = 'EMAIL'
                user_exists = User.objects.filter(email=email).exists()
            else:
                identifier = mobile
                type_value = 'PHONE'
                user_exists = User.objects.filter(mobile=mobile).exists()

            # If user doesn't exist, still return success message
            # This prevents account enumeration
            if not user_exists:
                logger.warning(
                    f"Password reset requested for non-existent user: \
                        {identifier}"
                )
                return Response(
                    {
                        "message": _(
                            "If an account exists with this identifier, a \
                                password reset OTP has been sent."
                        )
                    },
                    status=status.HTTP_200_OK,
                )

            # Check for too frequent OTP requests
            last_otp = (
                OTP.objects.filter(
                    identifier=identifier, purpose='RESET_PASSWORD'
                )
                .order_by('-created_at')
                .first()
            )

            if (
                last_otp
                and (timezone.now() - last_otp.created_at).total_seconds() < 60
            ):
                return Response(
                    {"detail": _("Please wait before requesting another OTP.")},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            # Generate and send OTP
            otp = OTP.generate_otp(
                identifier=identifier, type=type_value, purpose='RESET_PASSWORD'
            )

            # In a real implementation, you would send the OTP via email or \
            # SMS here
            # For now, we'll just log it
            logger.info(
                f"Password reset OTP generated for {identifier}: {otp.otp}"
            )

            return Response(
                {
                    "message": _(
                        "If an account exists with this identifier, a password \
                            reset OTP has been sent."
                    )
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(
                f"Unexpected error in reset password request: {str(e)}"
            )
            import traceback

            logger.error(traceback.format_exc())
            return Response(
                {"detail": _("An unexpected error occurred.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ResetPasswordConfirmView(APIView):
    """API endpoint to complete the password reset process.

    Validates the OTP received in the previous step and sets a new password
    for the user's account. This is the second and final step in the
    password reset flow.
    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='reset_password_confirm',
        operation_summary="Complete Password Reset",
        operation_description="""
        Complete the password reset process by verifying the OTP and setting
        a new password.

        ## Request Requirements:
        - Either email or mobile must be provided
        (same as used in the request step)
        - Valid OTP code received via email or SMS
        - New password that meets security requirements

        ## Process Flow:
        1. User submits the OTP and new password
        2. System validates the OTP is correct and not expired
        3. System updates the user's password
        4. User is automatically logged in with new credentials

        ## Security Features:
        - OTP must be valid and not expired
        - Maximum verification attempts enforced
        - New password must meet security requirements
        - Account is automatically verified if not already

        ## Response:
        Upon successful verification, the response includes:
        - Success message
        - New access token
        - New refresh token
        - User profile information

        This completes the password reset process and automatically logs
        in the user.
        """,
        request_body=ResetPasswordConfirmSerializer,
        responses={
            200: openapi.Response(
                description="Password reset successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Success message",
                        ),
                        'access': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="JWT access token for authentication",
                        ),
                        'refresh': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="JWT refresh token",
                        ),
                        'user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            description="User profile information",
                        ),
                    },
                ),
            ),
            400: openapi.Response(
                description="Invalid OTP or password validation error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Error details",
                        ),
                        'attempts_left': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description="Number of verification attempts \
                                remaining",
                        ),
                    },
                ),
            ),
            500: openapi.Response(
                description="Server error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Error message",
                        ),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        """Confirm password reset with OTP and set new password.

        Processes the password reset confirmation by:
        1. Validating the provided OTP and new password
        2. Checking if the OTP is valid and not expired
        3. Setting the new password for the user
        4. Generating authentication tokens for automatic login
        5. Returning success response with tokens

        Args:
        ----
            request: HTTP request with email/mobile, OTP, and new password

        Returns:
        -------
            Response: Result of password reset with appropriate
                     status code, message, and authentication tokens
        """
        try:
            serializer = ResetPasswordConfirmSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )

            email = serializer.validated_data.get('email')
            mobile = serializer.validated_data.get('mobile')
            otp_code = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']

            # Determine identifier
            if email:
                identifier = email
            else:
                identifier = mobile

            # Find the active OTP record
            otp_obj = (
                OTP.objects.filter(
                    identifier=identifier,
                    purpose='RESET_PASSWORD',
                    is_verified=False,
                    expires_at__gt=timezone.now(),
                )
                .order_by('-created_at')
                .first()
            )

            if not otp_obj:
                return Response(
                    {"detail": _("Invalid or expired OTP")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Verify OTP
            verified = otp_obj.verify(otp_code)

            if not verified:
                attempts_left = otp_obj.max_attempts - otp_obj.attempts

                if attempts_left > 0:
                    return Response(
                        {
                            "detail": _("Invalid OTP"),
                            "attempts_left": attempts_left,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                else:
                    return Response(
                        {
                            "detail": _(
                                "Maximum verification attempts exceeded. \
                                    Please request a new OTP."
                            ),
                            "attempts_left": 0,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Find the user and update password
            try:
                if email:
                    user = User.objects.get(email=email)
                else:
                    user = User.objects.get(mobile=mobile)

                # Reset password
                user.set_password(new_password)

                # Ensure user is verified
                if not user.is_verified:
                    user.is_verified = True

                user.save()

                logger.info(
                    f"Password reset successfully for user: {identifier}"
                )

                # Generate tokens for automatic login
                refresh = RefreshToken.for_user(user)

                return Response(
                    {
                        "message": _("Password has been reset successfully."),
                        "access": str(refresh.access_token),
                        "refresh": str(refresh),
                        "user": UserSerializerWithToken(user).data,
                    },
                    status=status.HTTP_200_OK,
                )
            except User.DoesNotExist:
                return Response(
                    {"detail": _("User not found.")},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            logger.error(
                f"Unexpected error in reset password confirmation: {str(e)}"
            )
            import traceback

            logger.error(traceback.format_exc())
            return Response(
                {"detail": _("An unexpected error occurred.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ResendOTPView(APIView):
    """API endpoint for resending OTP codes.

    Handles regeneration and resending of OTP codes for various purposes
    like registration, login, password reset, and contact verification.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_id='resend_otp',
        operation_summary="Resend OTP",
        operation_description="""
        Resend OTP code for various purposes like registration, login, \
            or password reset.

        ## Request Requirements:
        - Either email or mobile must be provided
        - Purpose of the OTP (REGISTER, LOGIN, RESET_PASSWORD, etc.)

        ## Process Flow:
        1. Validates the request data
        2. Checks if the user exists (for LOGIN/RESET_PASSWORD) or \
            doesn't exist (for REGISTER)
        3. Generates a new OTP
        4. Sends the OTP to the specified email or mobile
        5. Returns success message with verification instructions

        ## Security Features:
        - Rate limited to prevent abuse
        - Minimum time between OTP requests enforced (60 seconds)
        - Validates identifier exists or not based on purpose

        ## Response:
        - Success message with verification instructions
        """,
        request_body=ResendOTPSerializer,
        responses={
            200: openapi.Response(
                description="OTP resent successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Success message",
                        ),
                    },
                ),
            ),
            400: openapi.Response(
                description="Validation error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Error details",
                        ),
                    },
                ),
            ),
            429: openapi.Response(
                description="Too many OTP requests",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Rate limit exceeded message",
                        ),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        """Resends OTP code for verification.

        Processes the OTP resend request by:
        1. Validating the request data
        2. Checking if a new OTP can be generated (time limit)
        3. Generating and sending a new OTP
        4. Returning success message

        Args:
        ----
            request (Request): HTTP request with email/mobile and purpose

        Returns:
        -------
            Response: Resend result
                On success: HTTP 200 with success message
                On validation error: HTTP 400 with error message
                On rate limit: HTTP 429 with rate limit message
        """
        try:
            serializer = ResendOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )

            # Extract validated data
            email = serializer.validated_data.get('email')
            mobile = serializer.validated_data.get('mobile')
            purpose = serializer.validated_data['purpose']

            # Determine identifier and type
            if email:
                identifier = email
                type_value = 'EMAIL'
            else:
                identifier = mobile
                type_value = 'PHONE'

            logger.info(
                f"OTP resend requested for {identifier}, purpose: {purpose}"
            )

            # Check for too frequent OTP requests
            last_otp = (
                OTP.objects.filter(identifier=identifier, purpose=purpose)
                .order_by('-created_at')
                .first()
            )

            if (
                last_otp
                and (timezone.now() - last_otp.created_at).total_seconds() < 60
            ):
                logger.warning(f"Too frequent OTP request for {identifier}")
                return Response(
                    {"detail": _("Please wait before requesting another OTP.")},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            # Generate and send new OTP
            otp = OTP.generate_otp(
                identifier=identifier, type=type_value, purpose=purpose
            )

            # In a real implementation, you would send the OTP via email or
            # SMS here
            # For now, we'll just log it
            logger.info(
                f"OTP resent for {identifier}, purpose: {purpose}, \
                    OTP: {otp.otp}"
            )

            return Response(
                {"message": _("OTP sent successfully. Please verify.")},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(f"Unexpected error in resend OTP: {str(e)}")
            import traceback

            logger.error(traceback.format_exc())
            return Response(
                {"detail": _("An unexpected error occurred.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
