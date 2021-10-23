from django.db import models
import uuid


class User(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    date_joined = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)
    password = models.CharField(max_length=255)
    forget_link = models.BooleanField(default=False)

    class Meta:
        db_table = 'User'
