from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from users.models import SocialAccount


class SocialLoginSerializer(serializers.Serializer):
    """Serializer for social login requests.

    Handles validation and processing of social authentication tokens.
    """

    provider = serializers.ChoiceField(
        choices=SocialAccount.PROVIDER_CHOICES,
        help_text=_("Social provider (google, facebook, apple)"),
    )
    token = serializers.CharField(
        help_text=_("Authentication token from the social provider")
    )
    # Optional for connecting to existing account
    connect_to_account = serializers.BooleanField(
        required=False,
        default=False,
        help_text=_(
            "Whether to connect this social account to existing \
                    logged-in account"
        ),
    )

    def validate_provider(self, value):
        """Validate that the provider is supported."""
        value = value.lower()
        return value


class SocialAccountSerializer(serializers.ModelSerializer):
    """Serializer for social account details."""

    class Meta:
        model = SocialAccount
        fields = [
            'id',
            'provider',
            'email',
            'name',
            'profile_picture',
            'last_login',
            'created_at',
        ]
        read_only_fields = fields


class SocialAccountDisconnectSerializer(serializers.Serializer):
    """Serializer for disconnecting a social account."""

    provider = serializers.ChoiceField(
        choices=SocialAccount.PROVIDER_CHOICES,
        help_text=_("Social provider to disconnect"),
    )
