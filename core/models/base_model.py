import uuid

from django.db import models
from django.utils import timezone


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
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Timestamp when this record was created.",
    )
    updated_at = models.DateTimeField(
        auto_now=True, help_text="Timestamp when this record was last updated."
    )
    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when this record was soft deleted.",
    )

    objects = models.Manager()

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["is_active", "is_deleted"]),
        ]

    def soft_delete(self):
        """Soft delete the record by marking it as deleted"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=['is_deleted', 'deleted_at', 'updated_at'])

    def restore(self):
        """Restore a soft-deleted record"""
        self.is_deleted = False
        self.deleted_at = None
        self.save(update_fields=['is_deleted', 'deleted_at', 'updated_at'])
