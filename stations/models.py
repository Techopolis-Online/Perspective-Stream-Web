
from django.db import models
from users.models import CustomUser

class Station(models.Model):
	user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='stations')
	name = models.CharField(max_length=100)
	url = models.URLField()
	mount = models.CharField(max_length=100)
	enabled = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.name
