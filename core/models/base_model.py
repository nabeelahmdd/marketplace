import uuid

from django.db import models


class BaseModel(models.Model):
    """Abstract base model that provides common fields for all models.

    Includes fields for tracking creation, updates, active status, and soft \
        deletion of records.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Designates whether this record is active. Default is True.",
    )
    is_deleted = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Designates whether this record was deleted using soft \
            deletion. Default is False.",
    )
    created_on = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Timestamp when this record was created.",
    )
    updated_on = models.DateTimeField(
        auto_now=True, help_text="Timestamp when this record was last updated."
    )
    deleted_on = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when this record was soft deleted.",
    )
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="%(class)s_created",
    )
    updated_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="%(class)s_updated",
    )

    objects = models.Manager()

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["is_active", "is_deleted"]),
        ]
