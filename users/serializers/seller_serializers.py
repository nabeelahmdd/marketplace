import logging

from rest_framework import serializers

from users.models import Seller, SellerVerificationFile

# Initialize logger
logger = logging.getLogger(__name__)


class SellerVerificationFileSerializer(serializers.ModelSerializer):
    """Serializer for seller verification files.

    Handles the creation and retrieval of verification documents uploaded by\
          sellers.

    Attributes
    ----------
    id : UUID
        Unique identifier for the verification file
    file : FileField
        The uploaded verification document
    created_at : DateTimeField
        When the file was uploaded
    """

    class Meta:
        model = SellerVerificationFile
        fields = ['id', 'file', 'created_at']
        read_only_fields = ['id', 'created_at']


class SellerSerializer(serializers.ModelSerializer):
    """Serializer for seller profiles.

    Handles the creation, retrieval and update of seller profiles. The user is
    automatically assigned from the request context rather than being provided
    in the request data.

    Attributes
    ----------
    id : UUID
        Unique identifier for the seller profile
    name : str
        Business or store name
    id_number : str
        National ID or business registration number
    mobile : str
        Contact phone number for the seller (must be unique)
    is_company : bool
        Whether the seller is an individual (False) or company (True)
    owner_name : str
        For companies, the name of the owner or manager
    address : str
        Physical address of the seller
    verification_files : list
        Nested serializer for verification documents
    created_at : datetime
        When the profile was created
    updated_at : datetime
        When the profile was last updated
    """

    verification_files = SellerVerificationFileSerializer(
        many=True, read_only=True
    )

    class Meta:
        model = Seller
        fields = [
            'id',
            'name',
            'id_number',
            'mobile',
            'is_company',
            'owner_name',
            'address',
            'verification_files',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_mobile(self, value):
        """Validate that the mobile number is unique among sellers.

        Args:
        ----
            value (str): The mobile number to validate

        Returns:
        -------
            str: The validated mobile number

        Raises:
        ------
            serializers.ValidationError: If mobile number is already in use
        """
        if not value:
            return value

        # Check if mobile belongs to another seller
        instance = self.instance
        if (
            Seller.objects.exclude(id=instance.id if instance else None)
            .filter(mobile=value)
            .exists()
        ):
            raise serializers.ValidationError(
                "This mobile number is already in use by another seller."
            )
        return value


class SellerDetailSerializer(SellerSerializer):
    """Extended serializer for detailed seller information.

    Includes user details for comprehensive profile view.

    Additional Attributes
    --------------------
    user_name : str
        The full name of the user associated with this seller profile
    user_email : str
        The email address of the user
    user_is_verified : bool
        Whether the user's account has been verified
    """

    user_name = serializers.CharField(source='user.name', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_is_verified = serializers.BooleanField(
        source='user.is_verified', read_only=True
    )

    class Meta(SellerSerializer.Meta):
        fields = SellerSerializer.Meta.fields + [
            'user_name',
            'user_email',
            'user_is_verified',
        ]
