from django.contrib import admin
from .models import Users, Messages

# Register your models here.
admin.site.register(Users)
admin.site.register(Messages)
admin.site.site_header = "The Shield"
admin.site.site_title = "The Shield"