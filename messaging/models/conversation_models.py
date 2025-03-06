from django.db import models
from django.utils import timezone

from core.models import BaseModel
from listings.models import Listing
from users.models import User


class Conversation(BaseModel):
    """Chat conversations between users"""

    listing = models.ForeignKey(
        Listing,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='conversations',
    )
    participants = models.ManyToManyField(User, related_name='conversations')
    last_message_at = models.DateTimeField(auto_now_add=True)
    is_archived = models.BooleanField(default=False)

    class Meta:
        ordering = ['-last_message_at']

    def __str__(self):
        participants_str = ', '.join(
            [user.username for user in self.participants.all()[:2]]
        )
        return f"Conversation between {participants_str}"

    def update_last_message_time(self):
        """Update the last message timestamp"""
        self.last_message_at = timezone.now()
        self.save(update_fields=['last_message_at', 'updated_at'])


class Message(BaseModel):
    """Messages in conversations"""

    conversation = models.ForeignKey(
        Conversation, on_delete=models.CASCADE, related_name='messages'
    )
    sender = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='sent_messages'
    )
    content = models.TextField()
    attachment = models.FileField(
        upload_to='messages/attachments/', null=True, blank=True
    )
    read_by = models.ManyToManyField(
        User, related_name='read_messages', blank=True
    )

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"Message from {self.sender.username} in {self.conversation}"

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        super().save(*args, **kwargs)

        # Update conversation last message time when new message is created
        if is_new:
            self.conversation.update_last_message_time()

    def mark_as_read(self, user):
        """Mark message as read by user"""
        if user not in self.read_by.all():
            self.read_by.add(user)
