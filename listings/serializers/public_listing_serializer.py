from django.db import models
from django.utils import timezone
from drf_yasg.utils import swagger_serializer_method
from rest_framework import serializers

from listings.models import Comment, Listing, RecommendedListing, SavedSearch


class PublicListingSerializer(serializers.ModelSerializer):
    """Serializer for public marketplace listings.

    Provides a comprehensive representation of marketplace listings with
    related data like category information, seller details, and user-specific
    context. Includes calculated fields such as time since listing and distance
    from user.
    """

    total_comments = serializers.IntegerField(
        help_text="Total number of comments on this listing"
    )
    listing_time = serializers.SerializerMethodField(
        help_text="Human-readable time since listing was published"
    )
    distance = serializers.FloatField(
        required=False,
        help_text="Distance from user's location in kilometers \
            (only when coordinates provided)",
    )
    primary_image = serializers.SerializerMethodField(
        help_text="URL of the primary image for this listing"
    )
    category_name = serializers.CharField(
        source='category.name',
        read_only=True,
        help_text="Name of the listing category",
    )
    parent_category_name = serializers.CharField(
        source='category.parent.name',
        read_only=True,
        allow_null=True,
        help_text="Name of the parent category (if any)",
    )
    seller_name = serializers.CharField(
        source='seller.user.username',
        read_only=True,
        help_text="Username of the seller",
    )
    seller_rating = serializers.SerializerMethodField(
        help_text="Average rating of the seller (0-5 scale)"
    )
    is_favorited = serializers.SerializerMethodField(
        help_text="Whether the current user has favorited this listing"
    )
    days_until_expiry = serializers.SerializerMethodField(
        help_text="Number of days until this listing expires"
    )

    class Meta:
        model = Listing
        fields = [
            'id',
            'title',
            'slug',
            'price',
            'currency',
            'price_negotiable',
            'condition',
            'total_comments',
            'listing_time',
            'address',
            'city',
            'state',
            'postal_code',
            'country',
            'distance',
            'primary_image',
            'category_name',
            'parent_category_name',
            'view_count',
            'favorite_count',
            'is_featured',
            'seller_name',
            'seller_rating',
            'is_favorited',
            'published_at',
            'days_until_expiry',
        ]

    @swagger_serializer_method(serializer_or_field=serializers.CharField)
    def get_listing_time(self, obj):
        """Return time since listing was published in a human-readable format.

        Args:
        ----
            obj (Listing): Listing object

        Returns:
        -------
            str: Human-readable time string (e.g., "2 days ago")
        """
        if not obj.published_at:
            return "Not published yet"

        now = timezone.now()
        diff = now - obj.published_at

        if diff < timezone.timedelta(minutes=1):
            return "Just now"
        elif diff < timezone.timedelta(hours=1):
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif diff < timezone.timedelta(days=1):
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff < timezone.timedelta(days=30):
            days = diff.days
            return f"{days} day{'s' if days != 1 else ''} ago"
        elif diff < timezone.timedelta(days=365):
            months = diff.days // 30
            return f"{months} month{'s' if months != 1 else ''} ago"
        else:
            years = diff.days // 365
            return f"{years} year{'s' if years != 1 else ''} ago"

    @swagger_serializer_method(serializer_or_field=serializers.URLField)
    def get_primary_image(self, obj):
        """Get the URL of the primary image, if any.

        Args:
        ----
            obj (Listing): Listing object

        Returns:
        -------
            str: URL of the primary image or None
        """
        primary_image = obj.images.filter(is_primary=True).first()
        if primary_image:
            return self.context['request'].build_absolute_uri(
                primary_image.image.url
            )
        return None

    @swagger_serializer_method(serializer_or_field=serializers.FloatField)
    def get_seller_rating(self, obj):
        """Get the average rating of the seller.

        Args:
        ----
            obj (Listing): Listing object

        Returns:
        -------
            float: Average seller rating or 0.0
        """
        return (
            obj.seller.ratings.all().aggregate(avg_rating=models.Avg('value'))[
                'avg_rating'
            ]
            or 0.0
        )

    @swagger_serializer_method(serializer_or_field=serializers.BooleanField)
    def get_is_favorited(self, obj):
        """Check if the requesting user has favorited this listing.

        Args:
        ----
            obj (Listing): Listing object

        Returns:
        -------
            bool: True if favorited, False otherwise
        """
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.favorites.filter(
                user=request.user, is_active=True
            ).exists()
        return False

    @swagger_serializer_method(serializer_or_field=serializers.IntegerField)
    def get_days_until_expiry(self, obj):
        """Calculate days until listing expires.

        Args:
        ----
            obj (Listing): Listing object

        Returns:
        -------
            int: Number of days until expiry or None
        """
        if not obj.expires_at:
            return None
        days = (obj.expires_at - timezone.now()).days
        return max(0, days)  # Don't return negative days


class SavedSearchSerializer(serializers.ModelSerializer):
    """Serializer for user-saved searches.

    Includes the original search query details and alert preferences.
    Used for allowing users to save search queries for later reference
    and for setting up alerts for new matching listings.
    """

    query_text = serializers.CharField(
        source='search_query.query_text',
        read_only=True,
        help_text="The search query text",
    )
    result_count = serializers.IntegerField(
        source='search_query.result_count',
        read_only=True,
        help_text="Number of results this search returned when saved",
    )

    class Meta:
        model = SavedSearch
        fields = [
            'id',
            'name',
            'query_text',
            'result_count',
            'alert_enabled',
            'alert_frequency',
            'last_alert_sent_at',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'query_text',
            'result_count',
            'created_at',
            'updated_at',
        ]
        swagger_schema_fields = {
            'example': {
                'id': 1,
                'name': 'Furniture near me',
                'query_text': 'furniture',
                'result_count': 42,
                'alert_enabled': True,
                'alert_frequency': 'daily',
                'last_alert_sent_at': '2023-05-15T10:30:00Z',
                'created_at': '2023-05-10T14:23:45Z',
                'updated_at': '2023-05-10T14:23:45Z',
            }
        }


class RecommendedListingSerializer(serializers.ModelSerializer):
    """Serializer for personalized listing recommendations.

    Provides data about recommended listings including the recommendation
    score, reason, and tracking information about whether the user has
    viewed or clicked on the recommendation.
    """

    listing = serializers.SerializerMethodField(
        help_text="The recommended listing details"
    )

    class Meta:
        model = RecommendedListing
        fields = [
            'id',
            'listing',
            'score',
            'reason',
            'is_viewed',
            'is_clicked',
            'created_at',
        ]
        swagger_schema_fields = {
            'example': {
                'id': 1,
                'listing': {
                    'id': 123,
                    'title': 'Vintage Coffee Table',
                    'price': 150.00,
                    # Additional listing fields would be here
                },
                'score': 0.92,
                'reason': 'Based on your recent searches',
                'is_viewed': True,
                'is_clicked': False,
                'created_at': '2023-05-15T08:23:45Z',
            }
        }

    @swagger_serializer_method(serializer_or_field=PublicListingSerializer)
    def get_listing(self, obj):
        """Return the full listing representation.

        Args:
        ----
            obj (RecommendedListing): RecommendedListing object

        Returns:
        -------
            dict: Serialized listing data
        """
        from listings.serializers import ListingSerializer

        return ListingSerializer(obj.listing, context=self.context).data


class CommentSerializer(serializers.ModelSerializer):
    """Serializer for listing comments.

    Handles the serialization and deserialization of Comment objects.
    Includes user information and reply structure.
    """

    username = serializers.CharField(
        source='user.username',
        read_only=True,
        help_text="Username of the commenter",
    )
    user_id = serializers.IntegerField(
        source='user.id', read_only=True, help_text="ID of the commenter"
    )
    replies = serializers.SerializerMethodField(
        help_text="Replies to this comment"
    )
    time_since = serializers.SerializerMethodField(
        help_text="Human-readable time since comment was created"
    )

    class Meta:
        model = Comment
        fields = [
            'id',
            'content',
            'user_id',
            'username',
            'created_at',
            'updated_at',
            'time_since',
            'parent',
            'replies',
        ]
        read_only_fields = [
            'id',
            'created_at',
            'updated_at',
            'user_id',
            'username',
            'time_since',
            'replies',
        ]
        extra_kwargs = {
            'content': {'help_text': "Content of the comment"},
            'parent': {
                'help_text': "ID of parent comment if this is a reply",
                'required': False,
                'allow_null': True,
            },
        }
        swagger_schema_fields = {
            'example': {
                'id': 1,
                'content': "This looks amazing! Is it still available?",
                'user_id': 42,
                'username': "janedoe",
                'created_at': '2023-05-15T14:23:45Z',
                'updated_at': '2023-05-15T14:23:45Z',
                'time_since': '2 days ago',
                'parent': None,
                'replies': [
                    {
                        'id': 2,
                        'content': "Yes, it's still available!",
                        'user_id': 17,
                        'username': "johndoe",
                        'created_at': '2023-05-15T14:30:12Z',
                        'time_since': '2 days ago',
                    }
                ],
            }
        }

    @swagger_serializer_method(serializer_or_field=serializers.ListField)
    def get_replies(self, obj):
        """Get replies to this comment.

        Returns a simplified representation of child comments.

        Args:
        ----
            obj (Comment): Comment object

        Returns:
        -------
            list: List of reply comment data
        """
        # Only process if this is a parent comment
        if obj.parent is not None:
            return []

        # Get direct replies
        replies = Comment.objects.filter(parent=obj, is_approved=True).order_by(
            'created_at'
        )

        # Use a simplified representation for replies
        reply_data = []
        for reply in replies:
            reply_data.append(
                {
                    'id': reply.id,
                    'content': reply.content,
                    'user_id': reply.user.id,
                    'username': reply.user.username,
                    'created_at': reply.created_at,
                    'time_since': self.get_time_since(reply),
                }
            )

        return reply_data

    @swagger_serializer_method(serializer_or_field=serializers.CharField)
    def get_time_since(self, obj):
        """Get human-readable time since comment was created.

        Args:
        ----
            obj (Comment): Comment object

        Returns:
        -------
            str: Human-readable time string (e.g., "2 days ago")
        """
        from datetime import timedelta

        from django.utils import timezone

        now = timezone.now()
        diff = now - obj.created_at

        if diff < timedelta(minutes=1):
            return "Just now"
        elif diff < timedelta(hours=1):
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif diff < timedelta(days=1):
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff < timedelta(days=30):
            days = diff.days
            return f"{days} day{'s' if days != 1 else ''} ago"
        elif diff < timedelta(days=365):
            months = diff.days // 30
            return f"{months} month{'s' if months != 1 else ''} ago"
        else:
            years = diff.days // 365
            return f"{years} year{'s' if years != 1 else ''} ago"

    def validate_parent(self, value):
        """Validate the parent comment.

        Ensures that:
        1. Parent comment exists and is approved
        2. Parent is not already a reply (prevents nested replies)

        Args:
        ----
            value: Parent comment ID

        Returns:
        -------
            Comment: Parent comment object

        Raises:
        ------
            ValidationError: If parent validation fails
        """
        if value is None:
            return value

        if value.parent is not None:
            raise serializers.ValidationError(
                "Cannot reply to a reply. Please reply to the original comment."
            )

        if not value.is_approved:
            raise serializers.ValidationError(
                "Cannot reply to an unapproved comment."
            )

        return value

    def validate(self, data):
        """Validate the comment data.

        Performs cross-field validation.

        Args:
        ----
            data: Comment data

        Returns:
        -------
            dict: Validated data

        Raises:
        ------
            ValidationError: If validation fails
        """
        # Add any cross-field validation here
        return data

    def create(self, validated_data):
        """Create a new comment.

        Handles any special creation logic.

        Args:
        ----
            validated_data: Validated comment data

        Returns:
        -------
            Comment: Created comment
        """
        return Comment.objects.create(**validated_data)
