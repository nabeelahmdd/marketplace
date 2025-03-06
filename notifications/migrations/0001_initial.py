# Generated by Django 5.1.4 on 2025-03-06 15:34

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        (
            'listings',
            '0004_comment_joblisting_propertylisting_searchquery_and_more',
        ),
        ('messaging', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Notification',
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
                    'type',
                    models.CharField(
                        choices=[
                            ('message', 'New Message'),
                            ('comment', 'New Comment'),
                            ('favorite', 'New Favorite'),
                            ('rating', 'New Rating'),
                            ('offer', 'New Offer'),
                            ('listing_update', 'Listing Update'),
                            ('listing_expiring', 'Listing Expiring'),
                            ('account', 'Account Notification'),
                            ('promotion', 'Promotion'),
                            ('system', 'System Notification'),
                        ],
                        max_length=20,
                    ),
                ),
                ('title', models.CharField(max_length=255)),
                ('content', models.TextField()),
                ('image_url', models.URLField(blank=True, null=True)),
                ('is_read', models.BooleanField(default=False)),
                ('is_email_sent', models.BooleanField(default=False)),
                ('is_push_sent', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('read_at', models.DateTimeField(blank=True, null=True)),
                (
                    'conversation',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to='messaging.conversation',
                    ),
                ),
                (
                    'listing',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='notifications',
                        to='listings.listing',
                    ),
                ),
                (
                    'sender',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='sent_notifications',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='notifications',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [
                    models.Index(
                        fields=['user', 'is_read', 'created_at'],
                        name='notificatio_user_id_8a7c6b_idx',
                    )
                ],
            },
        ),
    ]
