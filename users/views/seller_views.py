import logging

from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from users.models import Seller, SellerVerificationFile
from users.serializers import (
    SellerDetailSerializer,
    SellerSerializer,
    SellerVerificationFileSerializer,
)

logger = logging.getLogger(__name__)


class SellerProfileView(APIView):
    """API endpoint for managing seller profiles.

    Allows users to create, retrieve, update, and delete their
    own seller profile.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        tags=["Seller"],
        operation_id="get_seller_profile",
        operation_summary="Get Seller Profile",
        operation_description=(
            "Retrieve the authenticated user's seller profile."
        ),
        responses={
            200: openapi.Response(
                description="Success",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    ref="#/components/schemas/SellerDetail",
                ),
            ),
            404: "Seller profile not found",
        },
    )
    def get(self, request):
        """Get the authenticated user's seller profile."""
        try:
            if not request.user.is_active or getattr(
                request.user, "is_deleted", False
            ):
                return Response(
                    {"detail": _("Account is inactive or has been deleted.")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                seller = Seller.objects.get(user=request.user)
                serializer = SellerDetailSerializer(seller)
                return Response(serializer.data)
            except Seller.DoesNotExist:
                return Response(
                    {"detail": _("You don't have a seller profile.")},
                    status=status.HTTP_404_NOT_FOUND,
                )
        except Exception as e:
            logger.error(f"Error retrieving seller profile: {str(e)}")
            return Response(
                {
                    "detail": _(
                        "An error occurred while retrieving the seller "
                        "profile."
                    )
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @swagger_auto_schema(
        tags=["Seller"],
        operation_id="create_seller_profile",
        operation_summary="Create Seller Profile",
        operation_description=(
            "Create a new seller profile for the authenticated user."
        ),
        request_body=SellerSerializer,
        responses={
            201: openapi.Response(
                description="Seller profile created",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT, ref="#/components/schemas/Seller"
                ),
            ),
            400: "Validation error or profile already exists",
        },
    )
    def post(self, request):
        """Create a new seller profile for the authenticated user."""
        try:
            if not request.user.is_active or getattr(
                request.user, "is_deleted", False
            ):
                return Response(
                    {
                        "detail": _(
                            "Inactive or deleted users cannot create seller "
                            "profiles."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if Seller.objects.filter(user=request.user).exists():
                return Response(
                    {
                        "detail": _(
                            "You already have a seller profile. Use PUT to \
                                update it."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = SellerSerializer(
                data=request.data, context={"request": request}
            )
            if serializer.is_valid():
                seller = serializer.save(user=request.user)
                request.user.is_seller = True
                request.user.save(update_fields=["is_seller"])

                logger.info(
                    f"Seller profile created for user {request.user.id}: "
                    f"{seller.name}"
                )

                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error creating seller profile: {str(e)}")
            return Response(
                {
                    "detail": _(
                        "An error occurred while creating the seller profile."
                    )
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @swagger_auto_schema(
        tags=["Seller"],
        operation_id="update_seller_profile",
        operation_summary="Update Seller Profile",
        operation_description=(
            "Update the authenticated user's seller profile."
        ),
        request_body=SellerSerializer,
        responses={
            200: openapi.Response(
                description="Seller profile updated",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT, ref="#/components/schemas/Seller"
                ),
            ),
            400: "Validation error",
            404: "Seller profile not found",
        },
    )
    def put(self, request):
        """Update the authenticated user's seller profile."""
        try:
            if not request.user.is_active or getattr(
                request.user, "is_deleted", False
            ):
                return Response(
                    {
                        "detail": _(
                            "Inactive or deleted users cannot update seller "
                            "profiles."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                seller = Seller.objects.get(user=request.user)
            except Seller.DoesNotExist:
                return Response(
                    {"detail": _("You don't have a seller profile to update.")},
                    status=status.HTTP_404_NOT_FOUND,
                )

            serializer = SellerSerializer(
                seller,
                data=request.data,
                partial=True,
                context={"request": request},
            )
            if serializer.is_valid():
                seller = serializer.save()
                logger.info(
                    f"Seller profile updated for user {request.user.id}: "
                    f"{seller.id}"
                )
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error updating seller profile: {str(e)}")
            return Response(
                {
                    "detail": _(
                        "An error occurred while updating the seller profile."
                    )
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @swagger_auto_schema(
        tags=["Seller"],
        operation_id="delete_seller_profile",
        operation_summary="Delete Seller Profile",
        operation_description=(
            "Delete the authenticated user's seller profile."
        ),
        responses={
            204: "Seller profile deleted",
            404: "Seller profile not found",
        },
    )
    def delete(self, request):
        """Delete the authenticated user's seller profile."""
        try:
            if not request.user.is_active or getattr(
                request.user, "is_deleted", False
            ):
                return Response(
                    {
                        "detail": _(
                            "Inactive or deleted users cannot delete seller "
                            "profiles."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                seller = Seller.objects.get(user=request.user)
            except Seller.DoesNotExist:
                return Response(
                    {"detail": _("You don't have a seller profile to delete.")},
                    status=status.HTTP_404_NOT_FOUND,
                )

            seller_id = seller.id
            seller.delete()
            request.user.is_seller = False
            request.user.save(update_fields=["is_seller"])

            logger.info(
                f"Seller profile deleted: {seller_id}, User: "
                f"{request.user.id}"
            )
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error deleting seller profile: {str(e)}")
            return Response(
                {
                    "detail": _(
                        "An error occurred while deleting the seller profile."
                    )
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class SellerVerificationFileView(APIView):
    """API endpoint for uploading and retrieving seller verification files."""

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        tags=["Seller"],
        operation_id="list_verification_files",
        operation_summary="List Verification Files",
        operation_description=(
            "Get all verification files for the authenticated user's seller "
            "profile."
        ),
        responses={
            200: openapi.Response(
                description="Success",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        ref="#/components/schemas/" "SellerVerificationFile",
                    ),
                ),
            ),
            400: "Missing seller profile",
        },
    )
    def get(self, request):
        """Get all verification files for the authenticated seller profile."""
        try:
            if not request.user.is_active or getattr(
                request.user, "is_deleted", False
            ):
                return Response(
                    {
                        "detail": _(
                            "Inactive or deleted users cannot access "
                            "verification files."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                seller = Seller.objects.get(user=request.user)
            except Seller.DoesNotExist:
                return Response(
                    {"detail": _("You must create a seller profile first.")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            verification_files = SellerVerificationFile.objects.filter(
                seller=seller
            )
            serializer = SellerVerificationFileSerializer(
                verification_files, many=True
            )
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error getting verification files: {str(e)}")
            return Response(
                {"detail": _("An error occurred while getting the files.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @swagger_auto_schema(
        tags=["Seller"],
        operation_id="upload_verification_file",
        operation_summary="Upload Verification File",
        operation_description=(
            "Upload a verification document for the seller profile.\n\n"
            "Request Requirements:\n"
            "- Must be authenticated\n"
            "- Must have a seller profile\n"
            "- File must be provided in form-data format\n\n"
            "Supported File Types:\n"
            "- PDF\n"
            "- JPEG/JPG\n"
            "- PNG"
        ),
        manual_parameters=[
            openapi.Parameter(
                name="file",
                in_=openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                required=True,
                description="Verification document file",
            )
        ],
        responses={
            201: openapi.Response(
                description="File uploaded successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    ref="#/components/schemas/SellerVerificationFile",
                ),
            ),
            400: "Invalid file or missing seller profile",
        },
    )
    def post(self, request):
        """Upload a verification file for the authenticated seller."""
        try:
            if not request.user.is_active or getattr(
                request.user, "is_deleted", False
            ):
                return Response(
                    {
                        "detail": _(
                            "Inactive or deleted users cannot upload "
                            "verification files."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                seller = Seller.objects.get(user=request.user)
            except Seller.DoesNotExist:
                return Response(
                    {"detail": _("You must create a seller profile first.")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if "file" not in request.FILES:
                return Response(
                    {"detail": _("No file provided.")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            file_obj = request.FILES["file"]
            verification_file = SellerVerificationFile.objects.create(
                seller=seller, file=file_obj
            )
            serializer = SellerVerificationFileSerializer(verification_file)
            logger.info(
                f"Verification file uploaded for seller: {seller.id}, "
                f"File: {verification_file.id}"
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error uploading verification file: {str(e)}")
            return Response(
                {"detail": _("An error occurred while uploading the file.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class SellerVerificationFileDetailView(APIView):
    """API endpoint for managing a specific verification file."""

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=["Seller"],
        operation_id="delete_verification_file",
        operation_summary="Delete Verification File",
        operation_description=(
            "Delete a specific verification file from the seller profile."
        ),
        responses={204: "File deleted successfully", 404: "File not found"},
    )
    def delete(self, request, file_id):
        """Delete a specific verification file."""
        try:
            if not request.user.is_active or getattr(
                request.user, "is_deleted", False
            ):
                return Response(
                    {
                        "detail": _(
                            "Inactive or deleted users cannot delete "
                            "verification files."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                file = SellerVerificationFile.objects.get(
                    id=file_id, seller__user=request.user
                )
            except SellerVerificationFile.DoesNotExist:
                return Response(
                    {"detail": _("File not found or permission denied.")},
                    status=status.HTTP_404_NOT_FOUND,
                )

            file_id_var = file.id
            seller_id = file.seller.id
            file.delete()

            logger.info(
                f"Verification file deleted: {file_id_var}, "
                f"Seller: {seller_id}"
            )
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error deleting verification file: {str(e)}")
            return Response(
                {"detail": _("An error occurred while deleting the file.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
