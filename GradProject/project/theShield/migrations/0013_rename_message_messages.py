# Generated by Django 5.1.4 on 2024-12-17 18:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('theShield', '0012_rename_messages_message'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Message',
            new_name='Messages',
        ),
    ]
