import logging
import secrets
import string

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from users.models import SocialAccount
from users.social_auth_validators import get_validator_for_provider

User = get_user_model()
logger = logging.getLogger(__name__)


def process_social_auth(provider, token, user=None):
    """Process social authentication and return or create a user.

    Args:
    ----
        provider: Social provider name
        token: Authentication token from the provider
        user: Optional existing user to connect account to

    Returns:
    -------
        Tuple of (user, created, social_account) where:
            - user is the authenticated User instance
            - created is a boolean indicating if the user was newly created
            - social_account is the SocialAccount instance

    Raises:
    ------
        serializers.ValidationError: If authentication fails
    """
    # Get validator for the provider
    validator = get_validator_for_provider(provider)

    # Validate token and get user info
    user_info = validator.validate(token)

    # If connecting to existing account
    if user is not None:
        # Check if this social account is already connected to another user
        existing_social = SocialAccount.objects.filter(
            provider=provider, provider_id=user_info['provider_id']
        ).first()

        if existing_social and existing_social.user.id != user.id:
            raise serializers.ValidationError(
                _("This social account is already connected to another user.")
            )

        # Connect social account to user
        social_account, created = SocialAccount.objects.update_or_create(
            provider=provider,
            provider_id=user_info['provider_id'],
            defaults={
                'user': user,
                'email': user_info.get('email'),
                'name': user_info.get('name', ''),
                'profile_picture': user_info.get('profile_picture'),
            },
        )

        return user, False, social_account

    # Check if we have a social account for this provider and provider_id
    social_account = SocialAccount.objects.filter(
        provider=provider, provider_id=user_info['provider_id']
    ).first()

    if social_account:
        # Return existing user
        return social_account.user, False, social_account

    # No existing social account, try to match by email
    email = user_info.get('email')
    if not email:
        raise serializers.ValidationError(
            _("Email not provided by social provider. Cannot create account.")
        )

    # Check if email is verified by provider
    if not user_info.get('email_verified', False):
        raise serializers.ValidationError(
            _(
                "Email not verified by social provider. Please verify your \
                    email first."
            )
        )

    # Check if user with this email exists
    user = User.objects.filter(email=email, is_deleted=False).first()
    created = False

    # If user doesn't exist, create a new one
    if not user:
        with transaction.atomic():
            # Create new user
            user = User(
                email=email,
                first_name=user_info.get('first_name', ''),
                last_name=user_info.get('last_name', ''),
                is_active=True,  # Social accounts are pre-verified
                account_verified=True,
                cr_by_self=True,
            )
            # Generate random password for the user
            password = ''.join(
                secrets.choice(string.ascii_letters + string.digits)
                for _ in range(16)
            )
            user.set_password(password)
            user.save()
            created = True

    # Create social account connection
    social_account = SocialAccount.objects.create(
        user=user,
        provider=provider,
        provider_id=user_info['provider_id'],
        email=user_info.get('email'),
        name=user_info.get('name', ''),
        profile_picture=user_info.get('profile_picture'),
    )

    return user, created, social_account
