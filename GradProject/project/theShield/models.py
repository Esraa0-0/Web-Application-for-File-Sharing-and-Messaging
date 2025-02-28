from django.db import models
from datetime import datetime
import uuid, os

# Define the dynamic file path function
def dynamic_file_path(instance, filename):
    #Generate a file path using the message_id
    return os.path.join('files', str(instance.message_id), filename)

# Create your models here.
class Users(models.Model):
    username = models.CharField(unique=True, max_length=30, primary_key=True)
    email = models.CharField(unique=True, max_length=50)
    password = models.CharField(max_length=30)
    private_key = models.TextField(unique=True)
    public_key = models.TextField(unique=True)
    created = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.username
    
    class Meta:
        verbose_name = 'User'
        
class Messages(models.Model):
    message_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sender = models.ForeignKey(Users, related_name='sent_messages', on_delete=models.CASCADE)
    recipient = models.ForeignKey(Users, related_name='received_messages', on_delete=models.CASCADE)
    ciphertext = models.BinaryField(null=True, blank=True)
    nonce = models.BinaryField(null=True, blank=True)
    tag = models.BinaryField(null=True, blank=True)
    attachment = models.FileField(upload_to=dynamic_file_path, null=True, blank=True)
    key = models.BinaryField(max_length=256, default=None)  # For a 2048-bit RSA key
    hash = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Message from {self.sender.username} to {self.recipient.username} at {self.timestamp}"

    class Meta:
        verbose_name = 'Message'
