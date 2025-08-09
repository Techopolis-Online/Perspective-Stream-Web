from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
from broadcasts.models import Broadcast
import jwt
import uuid


@login_required
@require_POST
def livekit_token(request):
	"""Return a LiveKit JWT access token for the authenticated user and broadcast.

	Expects JSON body: { "broadcast_id": <int> }
	"""
	if not settings.LIVEKIT_API_KEY or not settings.LIVEKIT_API_SECRET:
		return HttpResponseBadRequest("LiveKit not configured")

	try:
		data = request.POST or {}
		# For fetch with JSON, request.body; but keep simple form-encoded first
		if not data and request.body:
			import json
			data = json.loads(request.body.decode("utf-8"))
		broadcast_id = int(data.get("broadcast_id"))
	except Exception:
		return HttpResponseBadRequest("Invalid broadcast_id")

	try:
		broadcast = Broadcast.objects.get(pk=broadcast_id, user=request.user)
	except Broadcast.DoesNotExist:
		return HttpResponseForbidden("Not allowed")

	# Build claims: LiveKit style (video grants)
	now = int(timezone.now().timestamp())
	room_name = f"broadcast-{broadcast.pk}"
	identity = str(request.user.pk)
	claims = {
		"iss": settings.LIVEKIT_API_KEY,
		"exp": now + 60 * 10,
		"iat": now,
		"nbf": now - 5,
		"jti": str(uuid.uuid4()),
		"video": {
			"room": room_name,
			"roomCreate": True,
			"canPublish": True,
			"canPublishData": True,
			"canSubscribe": True,
			"identity": identity,
			"name": getattr(request.user, "display_name", str(request.user)),
		},
	}

	token = jwt.encode(claims, settings.LIVEKIT_API_SECRET, algorithm="HS256")
	return JsonResponse({
		"token": token,
		"url": settings.LIVEKIT_URL,
		"room": room_name,
		"identity": identity,
	})
