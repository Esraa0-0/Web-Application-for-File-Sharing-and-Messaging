# Generated by Django 5.1.4 on 2024-12-16 12:21

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('theShield', '0006_alter_users_private_key_alter_users_public_key'),
    ]

    operations = [
        migrations.AlterField(
            model_name='users',
            name='created',
            field=models.DateTimeField(default=datetime.datetime.now),
        ),
        migrations.AlterField(
            model_name='users',
            name='private_key',
            field=models.TextField(unique=True),
        ),
        migrations.AlterField(
            model_name='users',
            name='public_key',
            field=models.TextField(unique=True),
        ),
    ]
