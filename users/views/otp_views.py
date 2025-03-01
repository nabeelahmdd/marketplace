import logging

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from services import (
    format_purpose_for_message,
    send_otp_via_email,
    send_otp_via_sms,
)
from users.models import OTP
from users.serializers import (
    OTPLoginSerializer,
    OTPRegisterSerializer,
    RequestEmailOTPSerializer,
    RequestPhoneOTPSerializer,
    VerifyOTPSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)


class OTPRateThrottle(AnonRateThrottle):
    """Throttle class for OTP requests to prevent abuse.
    Limits OTP generation to 3 per hour per identifier.
    """

    rate = '1/min'
    scope = 'otp'


class RequestPhoneOTPView(APIView):
    """API endpoint to request an OTP via phone.

    Generates and sends a new OTP code to the provided phone number.
    """

    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    @swagger_auto_schema(
        tags=['OTP Authentication'],
        operation_id='request_phone_otp',
        operation_summary="Request Phone OTP",
        operation_description="""
        Request an OTP to be sent to a phone number.

        This endpoint generates a new OTP and sends it to the provided phone
        number.
        The OTP can be used for user registration, login, or password reset.

        ## Request Requirements:
        - Valid phone number with country code
        - Purpose of OTP request (REGISTER/LOGIN/RESET_PASSWORD)

        ## Process Flow:
        1. Validates phone number format
        2. Generates new OTP code
        3. Sends OTP via SMS
        4. Returns confirmation message

        ## Security:
        - Rate limited to prevent abuse (3 requests per hour per phone)
        - OTPs expire after 10 minutes
        - Maximum 3 verification attempts per OTP
        """,
        request_body=RequestPhoneOTPSerializer,
        responses={
            200: openapi.Response(
                description="OTP sent successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'debug_info': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'otp': openapi.Schema(type=openapi.TYPE_STRING),
                            },
                        ),
                    },
                ),
            ),
            400: "Validation error",
            429: "Too many OTP requests",
        },
    )
    def post(self, request):
        """Generate and send OTP to phone number.

        Args:
        ----
            request: HTTP request with phone number and purpose

        Returns:
        -------
            Response: Success message or error
        """
        # Get client IP for logging
        client_ip = self._get_client_ip(request)

        serializer = RequestPhoneOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        phone = serializer.validated_data['phone']
        purpose = serializer.validated_data['purpose']

        # For registration, check if phone is already registered
        if (
            purpose == 'REGISTER'
            and User.objects.filter(
                mobile=phone, is_active=True, is_deleted=False
            ).exists()
        ):
            return Response(
                {"phone": [_("This phone number is already registered")]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # For login and password reset, check if phone exists
        if (
            purpose in ['LOGIN', 'RESET_PASSWORD']
            and not User.objects.filter(
                mobile=phone, is_active=True, is_deleted=False
            ).exists()
        ):
            return Response(
                {"phone": [_("No account found with this phone number")]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Generate new OTP
        otp_obj = OTP.generate_otp(
            identifier=phone, type='PHONE', purpose=purpose
        )

        # Send OTP via SMS
        sent = send_otp_via_sms(
            phone, otp_obj.otp, format_purpose_for_message(purpose)
        )

        if not sent:
            logger.error(f"Failed to send OTP to {phone} from IP {client_ip}")
            return Response(
                {"detail": _("Failed to send OTP. Please try again later.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        logger.info(f"OTP sent to {phone} for {purpose} from IP {client_ip}")

        # Prepare response
        response_data = {"message": _("OTP sent successfully to your phone")}

        # Include OTP in development mode
        from django.conf import settings

        if settings.DEBUG:
            response_data["debug_info"] = {"otp": otp_obj.otp}

        return Response(response_data, status=status.HTTP_200_OK)

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class RequestEmailOTPView(APIView):
    """API endpoint to request an OTP via email.

    Generates and sends a new OTP code to the provided email address.
    """

    permission_classes = [AllowAny]
    # throttle_classes = [OTPRateThrottle]

    @swagger_auto_schema(
        tags=['OTP Authentication'],
        operation_id='request_email_otp',
        operation_summary="Request Email OTP",
        operation_description="""
        Request an OTP to be sent to an email address.

        This endpoint generates a new OTP and sends it to the provided email.
        The OTP can be used for user registration, login, or password reset.

        ## Request Requirements:
        - Valid email address
        - Purpose of OTP request (REGISTER/LOGIN/RESET_PASSWORD)

        ## Process Flow:
        1. Validates email format
        2. Generates new OTP code
        3. Sends OTP via email
        4. Returns confirmation message

        ## Security:
        - Rate limited to prevent abuse (3 requests per hour per email)
        - OTPs expire after 10 minutes
        - Maximum 3 verification attempts per OTP
        """,
        request_body=RequestEmailOTPSerializer,
        responses={
            200: openapi.Response(
                description="OTP sent successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'debug_info': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'otp': openapi.Schema(type=openapi.TYPE_STRING),
                            },
                        ),
                    },
                ),
            ),
            400: "Validation error",
            429: "Too many OTP requests",
        },
    )
    def post(self, request):
        """Generate and send OTP to email address.

        Args:
        ----
            request: HTTP request with email and purpose

        Returns:
        -------
            Response: Success message or error
        """
        # Get client IP for logging
        client_ip = self._get_client_ip(request)

        serializer = RequestEmailOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data['email']
        purpose = serializer.validated_data['purpose']

        # For registration, check if email is already registered
        if (
            purpose == 'REGISTER'
            and User.objects.filter(
                email=email, is_active=True, is_deleted=False
            ).exists()
        ):
            return Response(
                {"email": [_("This email is already registered")]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # For login and password reset, check if email exists
        if (
            purpose in ['LOGIN', 'RESET_PASSWORD']
            and not User.objects.filter(
                email=email, is_active=True, is_deleted=False
            ).exists()
        ):
            return Response(
                {"email": [_("No account found with this email")]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Generate new OTP
        otp_obj = OTP.generate_otp(
            identifier=email, type='EMAIL', purpose=purpose
        )

        # Send OTP via email
        sent = send_otp_via_email(
            email, otp_obj.otp, format_purpose_for_message(purpose)
        )

        if not sent:
            logger.error(f"Failed to send OTP to {email} from IP {client_ip}")
            return Response(
                {"detail": _("Failed to send OTP. Please try again later.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        logger.info(f"OTP sent to {email} for {purpose} from IP {client_ip}")

        # Prepare response
        response_data = {"message": _("OTP sent successfully to your email")}

        # Include OTP in development mode
        from django.conf import settings

        if settings.DEBUG:
            response_data["debug_info"] = {"otp": otp_obj.otp}

        return Response(response_data, status=status.HTTP_200_OK)

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class VerifyOTPView(APIView):
    """API endpoint to verify an OTP.

    Validates the provided OTP against the stored OTP record.
    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        tags=['OTP Authentication'],
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
                            "Maximum verification attempts exceeded. Please \
                                request a new OTP."
                        ),
                        "verified": False,
                        "attempts_left": 0,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # OTP verified successfully
        return Response(
            {"message": _("OTP verified successfully"), "verified": True},
            status=status.HTTP_200_OK,
        )


class OTPRegisterView(APIView):
    """API endpoint for user registration with OTP verification.

    Registers a new user after validating the OTP sent to their phone.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @swagger_auto_schema(
        tags=['OTP Authentication'],
        operation_id='otp_register',
        operation_summary="Register with OTP",
        operation_description="""
        Register a new user with OTP verification.

        This endpoint registers a new user after validating the OTP
        sent to their phone number. An optional email can also be provided.

        ## Request Requirements:
        - Phone number with valid OTP
        - Optional user profile information

        ## Process Flow:
        1. Verifies the OTP
        2. Creates a new user account
        3. Returns JWT tokens for immediate login

        ## Security:
        - OTP must be verified before registration
        - Phone number uniqueness is enforced
        - Email uniqueness is enforced if provided
        """,
        request_body=OTPRegisterSerializer,
        responses={
            201: openapi.Response(
                description="User registered successfully",
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
            400: "Validation error or invalid OTP",
            429: "Too many registration attempts",
        },
    )
    def post(self, request):
        """Register a new user with OTP verification.

        Args:
        ----
            request: HTTP request with registration data and OTP

        Returns:
        -------
            Response: Registration result with tokens
        """
        # Get client IP for logging
        client_ip = self._get_client_ip(request)

        serializer = OTPRegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        phone = serializer.validated_data['phone']
        otp_code = serializer.validated_data['otp']
        email = serializer.validated_data.get('email')
        first_name = serializer.validated_data.get('first_name', '')
        last_name = serializer.validated_data.get('last_name', '')

        # Check if the phone number is already registered
        if User.objects.filter(
            mobile=phone, is_active=True, is_deleted=False
        ).exists():
            return Response(
                {"phone": [_("This phone number is already registered")]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify OTP
        otp_obj = (
            OTP.objects.filter(
                identifier=phone,
                purpose='REGISTER',
                is_verified=False,
                expires_at__gt=timezone.now(),
            )
            .order_by('-created_at')
            .first()
        )

        if not otp_obj or not otp_obj.verify(otp_code):
            return Response(
                {"otp": [_("Invalid or expired OTP")]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # OTP verified, create new user
        try:
            with transaction.atomic():
                # Generate a random password for the user
                import secrets
                import string

                random_password = ''.join(
                    secrets.choice(string.ascii_letters + string.digits)
                    for _ in range(16)
                )

                # Determine country code
                country_code = None
                if phone.startswith('+'):
                    # Extract country code from the phone number
                    import re

                    match = re.match(r'^\+(\d+)', phone)
                    if match:
                        country_code = f"+{match.group(1)}"

                # Create user
                user = User(
                    mobile=phone,
                    country_code=country_code,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    is_active=True,
                    account_verified=True,
                    cr_by_self=True,
                )
                user.set_password(random_password)
                user.save()

                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)

                # Update last login IP
                if client_ip:
                    user.last_login_ip = client_ip
                    user.save(update_fields=['last_login_ip', 'last_login'])

                logger.info(
                    f"User registered via OTP: {phone} from IP {client_ip}"
                )

                # Get user serializer
                from users.serializers import UserSerializerWithToken

                return Response(
                    {
                        "message": _("Registration successful"),
                        "access": str(refresh.access_token),
                        "refresh": str(refresh),
                        "user": UserSerializerWithToken(user).data,
                    },
                    status=status.HTTP_201_CREATED,
                )

        except Exception as e:
            logger.error(f"Error during OTP registration: {str(e)}")
            return Response(
                {"detail": _("Registration failed. Please try again.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class OTPLoginView(APIView):
    """API endpoint for user login with OTP verification.

    Authenticates a user after validating the OTP sent to their phone.
    """

    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    @swagger_auto_schema(
        tags=['OTP Authentication'],
        operation_id='otp_login',
        operation_summary="Login with OTP",
        operation_description="""
        Login with OTP verification.

        This endpoint authenticates a user using the OTP sent to their
        phone number or email address, without requiring a password.

        ## Request Requirements:
        - Phone number OR email address with valid OTP

        ## Process Flow:
        1. Verifies the OTP
        2. Finds the associated user account
        3. Returns JWT tokens for login

        ## Security:
        - OTP must be verified before login
        - Phone number/email must exist in the system
        - Rate limited to prevent abuse
        """,
        request_body=OTPLoginSerializer,
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
            400: "Validation error or invalid OTP",
            404: "User not found",
            429: "Too many login attempts",
        },
    )
    def post(self, request):
        """Login with OTP verification.

        Args:
        ----
            request: HTTP request with phone/email and OTP

        Returns:
        -------
            Response: Login result with tokens
        """
        # Get client IP for logging
        client_ip = self._get_client_ip(request)

        serializer = OTPLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        phone = serializer.validated_data.get('phone')
        email = serializer.validated_data.get('email')
        otp_code = serializer.validated_data['otp']

        # Determine identifier and find the user
        identifier = phone if phone else email

        if phone:
            user = User.objects.filter(
                mobile=phone, is_active=True, is_deleted=False
            ).first()
            if not user:
                return Response(
                    {"phone": [_("No account found with this phone number")]},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:  # email
            user = User.objects.filter(
                email=email, is_active=True, is_deleted=False
            ).first()
            if not user:
                return Response(
                    {"email": [_("No account found with this email")]},
                    status=status.HTTP_404_NOT_FOUND,
                )

        # Verify OTP
        otp_obj = (
            OTP.objects.filter(
                identifier=identifier,
                purpose='LOGIN',
                is_verified=False,
                expires_at__gt=timezone.now(),
            )
            .order_by('-created_at')
            .first()
        )

        if not otp_obj or not otp_obj.verify(otp_code):
            return Response(
                {"otp": [_("Invalid or expired OTP")]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # OTP verified, login user
        try:
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            # Update last login IP
            if client_ip:
                user.last_login_ip = client_ip
                user.save(update_fields=['last_login_ip', 'last_login'])

            logger.info(
                f"User logged in via OTP: {identifier} from IP {client_ip}"
            )

            # Get user serializer
            from users.serializers import UserSerializerWithToken

            return Response(
                {
                    "message": _("Login successful"),
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "user": UserSerializerWithToken(user).data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error during OTP login: {str(e)}")
            return Response(
                {"detail": _("Login failed. Please try again.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
