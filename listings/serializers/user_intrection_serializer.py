# serializers.py

from rest_framework import serializers

from listings.models import Comment, Favorite, Rating


class FavoriteSerializer(serializers.ModelSerializer):
    """Serializer for the Favorite model.

    Represents a user's saved listing. The 'user' and 'created_at'
    fields are read-only.
    """

    class Meta:
        model = Favorite
        fields = ['id', 'user', 'listing', 'created_at', 'is_active']
        read_only_fields = ['id', 'created_at']


class CommentSerializer(serializers.ModelSerializer):
    """Serializer for the Comment model.

    Serializes comments on listings along with their replies.
    """

    # Optionally, include serialized replies to this comment.
    replies = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Comment
        fields = [
            'id',
            'listing',
            'user',
            'content',
            'parent',
            'replies',
            'is_approved',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_approved']

    def get_replies(self, obj):
        """Return serialized replies for the given comment."""
        if obj.replies.exists():
            return CommentSerializer(obj.replies.all(), many=True).data
        return []


class RatingSerializer(serializers.ModelSerializer):
    """Serializer for the Rating model.

    Represents a user's rating on a listing. The 'user', 'created_at',
    and 'updated_at' fields are read-only.
    """

    class Meta:
        model = Rating
        fields = [
            'id',
            'listing',
            'user',
            'value',
            'review',
            'is_approved',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_approved']
