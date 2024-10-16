from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


class url_detection(models.Model):
    url = models.CharField(max_length=100)
    result = models.TextField()
    date_posted = models.DateTimeField(default=timezone.now)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.url
