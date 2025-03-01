import logging

import jwt
import requests
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from rest_framework import serializers

logger = logging.getLogger(__name__)


class GoogleSocialAuthValidator:
    """Validator for Google OAuth tokens.

    Handles verification of Google ID tokens and extraction of user information.
    """

    @staticmethod
    def validate(token):
        """Validate a Google ID token and extract user information.

        Args:
        ----
            token: Google ID token to validate

        Returns:
        -------
            Dictionary with user information from the token

        Raises:
        ------
            serializers.ValidationError: If token validation fails
        """
        try:
            idinfo = google_id_token.verify_oauth2_token(
                token, google_requests.Request(), settings.GOOGLE_CLIENT_ID
            )

            # Verify issuer
            if idinfo['iss'] not in [
                'accounts.google.com',
                'https://accounts.google.com',
            ]:
                raise serializers.ValidationError(_("Invalid token issuer"))

            return {
                'provider_id': idinfo['sub'],
                'email': idinfo.get('email'),
                'name': idinfo.get('name', ''),
                'first_name': idinfo.get('given_name', ''),
                'last_name': idinfo.get('family_name', ''),
                'profile_picture': idinfo.get('picture', None),
                'email_verified': idinfo.get('email_verified', False),
            }
        except ValueError as e:
            logger.error(f"Google token validation error: {str(e)}")
            raise serializers.ValidationError(_("Invalid token"))


class FacebookSocialAuthValidator:
    """Validator for Facebook OAuth tokens.

    Handles verification of Facebook access tokens and extraction of user \
        information.
    """

    @staticmethod
    def validate(token):
        """Validate a Facebook access token and extract user information.

        Args:
        ----
            token: Facebook access token to validate

        Returns:
        -------
            Dictionary with user information from the token

        Raises:
        ------
            serializers.ValidationError: If token validation fails
        """
        try:
            # First verify the token
            app_id = settings.FACEBOOK_APP_ID
            app_secret = settings.FACEBOOK_APP_SECRET

            # Debug token endpoint to verify token validity
            debug_url = f"https://graph.facebook.com/debug_token?input_token={token}&access_token={app_id}|{app_secret}"
            debug_response = requests.get(debug_url)
            debug_data = debug_response.json()

            if (
                debug_response.status_code != 200
                or 'data' not in debug_data
                or not debug_data['data'].get('is_valid')
            ):
                raise serializers.ValidationError(_("Invalid Facebook token"))

            # Get user data from the token
            user_url = f"https://graph.facebook.com/me?fields=id,name,email,first_name,last_name,picture&access_token={token}"
            user_response = requests.get(user_url)
            user_data = user_response.json()

            if user_response.status_code != 200 or 'id' not in user_data:
                raise serializers.ValidationError(
                    _("Failed to get user data from Facebook")
                )

            return {
                'provider_id': user_data['id'],
                'email': user_data.get('email'),
                'name': user_data.get('name', ''),
                'first_name': user_data.get('first_name', ''),
                'last_name': user_data.get('last_name', ''),
                'profile_picture': user_data.get('picture', {})
                .get('data', {})
                .get('url'),
                'email_verified': True,  # Facebook verifies email
            }
        except Exception as e:
            logger.error(f"Facebook token validation error: {str(e)}")
            raise serializers.ValidationError(
                _("Invalid token or network error")
            )


class AppleSocialAuthValidator:
    """Validator for Apple Sign In tokens.

    Handles verification of Apple ID tokens and extraction of user information.
    """

    @staticmethod
    def validate(token):
        """Validate an Apple ID token and extract user information.

        Args:
        ----
            token: Apple ID token to validate

        Returns:
        -------
            Dictionary with user information from the token

        Raises:
        ------
            serializers.ValidationError: If token validation fails
        """
        try:
            # Get Apple's public keys
            keys_url = 'https://appleid.apple.com/auth/keys'
            keys_response = requests.get(keys_url)
            keys_data = keys_response.json()

            # Decode token without verification first to get header
            unverified_header = jwt.get_unverified_header(token)

            # Find the right key
            key = None
            for k in keys_data['keys']:
                if k['kid'] == unverified_header['kid']:
                    key = k
                    break

            if key is None:
                raise serializers.ValidationError(
                    _("Invalid token: Key not found")
                )

            # Import key for verification
            from jwt.algorithms import RSAAlgorithm

            public_key = RSAAlgorithm.from_jwk(key)

            # Verify token
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=settings.APPLE_CLIENT_ID,
                verify=True,
            )

            # Check if token is properly decoded
            if 'sub' not in decoded:
                raise serializers.ValidationError(_("Invalid token format"))

            # Note: Apple tokens might not include name/email after the first
            # sign-in
            # For first-time sign-ins, client may pass additional user data
            return {
                'provider_id': decoded['sub'],
                'email': decoded.get('email'),
                'name': '',  # Apple doesn't consistently provide name
                'first_name': '',
                'last_name': '',
                'profile_picture': None,
                'email_verified': decoded.get('email_verified', False),
            }
        except jwt.exceptions.PyJWTError as e:
            logger.error(f"Apple token validation error: {str(e)}")
            raise serializers.ValidationError(_("Invalid token"))
        except Exception as e:
            logger.error(f"Apple token validation error: {str(e)}")
            raise serializers.ValidationError(
                _("Invalid token or network error")
            )


def get_validator_for_provider(provider):
    """Get the appropriate validator for a social provider.

    Args:
    ----
        provider: Social provider name (google, facebook, apple)

    Returns:
    -------
        Validator class for the provider

    Raises:
    ------
        serializers.ValidationError: If provider is not supported
    """
    validators = {
        'google': GoogleSocialAuthValidator,
        'facebook': FacebookSocialAuthValidator,
        'apple': AppleSocialAuthValidator,
    }

    validator = validators.get(provider.lower())
    if not validator:
        raise serializers.ValidationError(_("Unsupported social provider"))

    return validator
