
from django.db import models
from users.models import CustomUser

class Broadcast(models.Model):
	PRIVACY_CHOICES = [
		('public', 'Public'),
		('unlisted', 'Unlisted'),
		('private', 'Private'),
	]
	user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='broadcasts')
	title = models.CharField(max_length=255)
	description = models.TextField(blank=True)
	category = models.CharField(max_length=100, blank=True)
	tags = models.CharField(max_length=255, blank=True)
	start_time = models.DateTimeField()
	privacy = models.CharField(max_length=10, choices=PRIVACY_CHOICES, default='public')
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	youtube_id = models.CharField(max_length=128, blank=True)
	radio_station = models.CharField(max_length=128, blank=True)
	is_live = models.BooleanField(default=False)

	def __str__(self):
		return self.title
