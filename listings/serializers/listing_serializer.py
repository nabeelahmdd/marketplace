from rest_framework import serializers

from listings.models import Listing, ListingImage


class ListingImageSerializer(serializers.ModelSerializer):
    """Serializer for listing images.

    Handles the representation of ListingImage objects in the API,
    including their relationship to listings.
    """

    class Meta:
        model = ListingImage
        fields = [
            'id',
            'image',
            'alt_text',
            'is_primary',
            'order',
            'created_at',
        ]
        read_only_fields = ['created_at']


class ListingSerializer(serializers.ModelSerializer):
    """Serializer for marketplace listings.

    Handles the creation, updating, and representation of Listing objects
    in the API, including seller information and related images.
    """

    seller = serializers.StringRelatedField(read_only=True)
    images = ListingImageSerializer(many=True, read_only=True)

    class Meta:
        model = Listing
        fields = [
            'id',
            'title',
            'slug',
            'description',
            'price',
            'price_negotiable',
            'currency',
            'category',
            'seller',
            'status',
            'condition',
            'location',
            'address',
            'city',
            'state',
            'postal_code',
            'country',
            'view_count',
            'favorite_count',
            'published_at',
            'expires_at',
            'images',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'slug',
            'seller',
            'view_count',
            'favorite_count',
            'published_at',
            'expires_at',
            'created_at',
            'updated_at',
        ]

    def create(self, validated_data):
        """Ensure seller is set automatically to the currently
        authenticated user.

        Args:
        ----
            validated_data: The validated data for creating a listing.

        Returns:
        -------
            Listing: The newly created listing instance.
        """
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['seller'] = request.user.seller
        return super().create(validated_data)

    def update(self, instance, validated_data):
        """Prevent seller field modification during updates.

        Args:
        ----
            instance: The existing listing instance.
            validated_data: The validated data for updating the listing.

        Returns:
        -------
            Listing: The updated listing instance.
        """
        validated_data.pop('seller', None)  # Prevent changing seller
        return super().update(instance, validated_data)


class ListingDetailSerializer(ListingSerializer):
    """Extended serializer for detailed listing views.

    Provides additional fields and information useful for detailed
    views of a specific listing.
    """

    category_name = serializers.ReadOnlyField(source='category.name')
    seller_name = serializers.ReadOnlyField(source='seller.user.get_full_name')

    class Meta(ListingSerializer.Meta):
        fields = ListingSerializer.Meta.fields + [
            'category_name',
            'seller_name',
        ]
