# Generated by Django 5.1.4 on 2024-12-17 19:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('theShield', '0015_messages_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='messages',
            name='hash',
            field=models.TextField(blank=True, null=True),
        ),
    ]
