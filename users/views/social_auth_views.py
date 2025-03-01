import logging

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from services import process_social_auth
from users.models import SocialAccount
from users.serializers import (
    SocialAccountDisconnectSerializer,
    SocialAccountSerializer,
    SocialLoginSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)


class SocialLoginView(APIView):
    """API endpoint for social login/registration.

    Handles social authentication tokens and converts them to JWT tokens.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @swagger_auto_schema(
        tags=['Social Authentication'],
        operation_id='social_login',
        operation_summary="Social Login/Register",
        operation_description="""
        Authenticate with a social provider (Google, Facebook, Apple) using
        OAuth token.

        This endpoint:
        1. Validates the social provider token
        2. Creates or retrieves a user account based on the token
        3. Returns JWT tokens for API authentication

        If a user with the email from the social account already exists, the
        social account will be linked to the existing user. Otherwise, a new
        user will be created.

        ## Supported Providers:
        - Google ('google')
        - Facebook ('facebook')
        - Apple ('apple')

        ## Process Flow:
        1. Validates social provider token
        2. Extracts user information
        3. Creates or retrieves user account
        4. Links social account to user
        5. Returns JWT tokens and user data

        ## Security:
        - Rate limited to prevent abuse
        - Token validation through official provider APIs
        - Email verification required from provider
        """,
        request_body=SocialLoginSerializer,
        responses={
            200: openapi.Response(
                description="Login/registration successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                        'created': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    },
                ),
            ),
            400: "Invalid token or provider",
            429: "Too many login attempts",
        },
    )
    def post(self, request):
        """Process social login request and return JWT tokens.

        Args:
        ----
            request: HTTP request with provider and token

        Returns:
        -------
            Response: JWT tokens and user data
        """
        # Get client IP for logging
        client_ip = self._get_client_ip(request)

        serializer = SocialLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        provider = serializer.validated_data['provider']
        token = serializer.validated_data['token']
        connect_to_account = serializer.validated_data.get(
            'connect_to_account', False
        )

        try:
            # If connecting to existing account, user must be authenticated
            if connect_to_account:
                if not request.user.is_authenticated:
                    return Response(
                        {
                            "detail": _(
                                "Authentication required to connect social \
                                    account"
                            )
                        },
                        status=status.HTTP_401_UNAUTHORIZED,
                    )
                user = request.user
            else:
                user = None

            # Process social authentication
            user, created, social_account = process_social_auth(
                provider, token, user
            )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            # Update last login IP if available
            if client_ip:
                user.last_login_ip = client_ip
                user.save(update_fields=['last_login_ip', 'last_login'])

            logger.info(
                f"User {'created and' if created else ''} logged in via \
                    {provider}: {user.email} from IP: {client_ip}"
            )

            # Get user serializer
            from users.serializers import UserSerializerWithToken

            return Response(
                {
                    'message': _('Login successful'),
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': UserSerializerWithToken(user).data,
                    'created': created,
                    'social_account': SocialAccountSerializer(
                        social_account
                    ).data,
                },
                status=status.HTTP_200_OK,
            )

        except serializers.ValidationError as e:
            logger.warning(
                f"Social login validation error for {provider} from IP \
                    {client_ip}: {str(e)}"
            )
            return Response(
                {"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.error(
                f"Social login error for {provider} from IP \
                    {client_ip}: {str(e)}"
            )
            return Response(
                {
                    "detail": _(
                        "An error occurred during social login. Please \
                            try again."
                    )
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class SocialAccountsView(APIView):
    """API endpoint for viewing connected social accounts.

    Lists all social accounts connected to the authenticated user.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['Social Authentication'],
        operation_id='list_social_accounts',
        operation_summary="List Connected Social Accounts",
        operation_description="""
        List all social accounts connected to the authenticated user.

        This endpoint returns all social provider accounts (Google, Facebook, \
            Apple)
        that have been linked to the current user's account.
        """,
        responses={
            200: openapi.Response(
                description="List of connected social accounts",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'provider': openapi.Schema(
                                type=openapi.TYPE_STRING
                            ),
                            'email': openapi.Schema(type=openapi.TYPE_STRING),
                            'name': openapi.Schema(type=openapi.TYPE_STRING),
                            'profile_picture': openapi.Schema(
                                type=openapi.TYPE_STRING
                            ),
                            'last_login': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                format=openapi.FORMAT_DATETIME,
                            ),
                            'created_at': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                format=openapi.FORMAT_DATETIME,
                            ),
                        },
                    ),
                ),
            ),
            401: "Authentication required",
        },
    )
    def get(self, request):
        """List connected social accounts.

        Args:
        ----
            request: HTTP request from authenticated user

        Returns:
        -------
            Response: List of connected social accounts
        """
        social_accounts = SocialAccount.objects.filter(user=request.user)
        serializer = SocialAccountSerializer(social_accounts, many=True)
        return Response(serializer.data)


class SocialAccountDisconnectView(APIView):
    """API endpoint for disconnecting a social account.

    Disconnects a social provider from the authenticated user's account.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['Social Authentication'],
        operation_id='disconnect_social_account',
        operation_summary="Disconnect Social Account",
        operation_description="""
        Disconnect a social provider from the authenticated user's account.

        This endpoint removes the link between a social provider \
            (Google, Facebook, Apple)
        and the user's account. The user will no longer be able to login using \
            this provider.

        Note: If the user has no password set and this is their only login \
            method,
        they will need to use password reset to regain access to their account.
        """,
        request_body=SocialAccountDisconnectSerializer,
        responses={
            200: openapi.Response(
                description="Social account disconnected",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            400: "Validation error",
            401: "Authentication required",
            404: "Social account not found",
        },
    )
    def post(self, request):
        """Disconnect a social account.

        Args:
        ----
            request: HTTP request with provider to disconnect

        Returns:
        -------
            Response: Success message or error
        """
        serializer = SocialAccountDisconnectSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        provider = serializer.validated_data['provider']

        # Find and delete the social account
        try:
            social_account = SocialAccount.objects.get(
                user=request.user, provider=provider
            )
            social_account.delete()

            logger.info(
                f"User {request.user.email} disconnected {provider} social \
                    account"
            )

            return Response(
                {'message': _('Social account disconnected successfully')}
            )
        except SocialAccount.DoesNotExist:
            return Response(
                {
                    "detail": _(
                        "No connected social account found for this provider"
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )
