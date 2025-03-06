# Generated by Django 5.1.4 on 2025-03-06 15:32

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        (
            'listings',
            '0004_comment_joblisting_propertylisting_searchquery_and_more',
        ),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Conversation',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'uuid',
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, unique=True
                    ),
                ),
                (
                    'is_active',
                    models.BooleanField(
                        db_index=True,
                        default=True,
                        help_text='Designates whether this record is active. Default is True.',
                    ),
                ),
                (
                    'is_deleted',
                    models.BooleanField(
                        db_index=True,
                        default=False,
                        help_text='Designates whether this record was deleted using soft             deletion. Default is False.',
                    ),
                ),
                (
                    'created_at',
                    models.DateTimeField(
                        auto_now_add=True,
                        db_index=True,
                        help_text='Timestamp when this record was created.',
                    ),
                ),
                (
                    'updated_at',
                    models.DateTimeField(
                        auto_now=True,
                        help_text='Timestamp when this record was last updated.',
                    ),
                ),
                (
                    'deleted_at',
                    models.DateTimeField(
                        blank=True,
                        help_text='Timestamp when this record was soft deleted.',
                        null=True,
                    ),
                ),
                ('last_message_at', models.DateTimeField(auto_now_add=True)),
                ('is_archived', models.BooleanField(default=False)),
                (
                    'listing',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='conversations',
                        to='listings.listing',
                    ),
                ),
                (
                    'participants',
                    models.ManyToManyField(
                        related_name='conversations',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['-last_message_at'],
            },
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'uuid',
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, unique=True
                    ),
                ),
                (
                    'is_active',
                    models.BooleanField(
                        db_index=True,
                        default=True,
                        help_text='Designates whether this record is active. Default is True.',
                    ),
                ),
                (
                    'is_deleted',
                    models.BooleanField(
                        db_index=True,
                        default=False,
                        help_text='Designates whether this record was deleted using soft             deletion. Default is False.',
                    ),
                ),
                (
                    'created_at',
                    models.DateTimeField(
                        auto_now_add=True,
                        db_index=True,
                        help_text='Timestamp when this record was created.',
                    ),
                ),
                (
                    'updated_at',
                    models.DateTimeField(
                        auto_now=True,
                        help_text='Timestamp when this record was last updated.',
                    ),
                ),
                (
                    'deleted_at',
                    models.DateTimeField(
                        blank=True,
                        help_text='Timestamp when this record was soft deleted.',
                        null=True,
                    ),
                ),
                ('content', models.TextField()),
                (
                    'attachment',
                    models.FileField(
                        blank=True, null=True, upload_to='messages/attachments/'
                    ),
                ),
                (
                    'conversation',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='messages',
                        to='messaging.conversation',
                    ),
                ),
                (
                    'read_by',
                    models.ManyToManyField(
                        blank=True,
                        related_name='read_messages',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    'sender',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='sent_messages',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['created_at'],
            },
        ),
    ]
