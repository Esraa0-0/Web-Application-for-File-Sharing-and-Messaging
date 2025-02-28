# Generated by Django 5.1.4 on 2024-12-21 14:10

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('theShield', '0017_messages_is_read'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='messages',
            name='id',
        ),
        migrations.AddField(
            model_name='messages',
            name='message_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
        ),
    ]
