
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Broadcast
from stations.models import Station
from .forms import BroadcastForm
from django.utils import timezone

@login_required
def broadcast_list(request):
	broadcasts = Broadcast.objects.filter(user=request.user).order_by('-start_time')
	return render(request, 'broadcasts/list.html', {'broadcasts': broadcasts})

@login_required
def broadcast_create(request):
	if request.method == 'POST':
		form = BroadcastForm(request.POST)
		if form.is_valid():
			broadcast = form.save(commit=False)
			broadcast.user = request.user
			if form.cleaned_data.get('go_live_now'):
				broadcast.start_time = timezone.now()
				broadcast.is_live = True
			# Persist destination choices
			broadcast.enable_radio = form.cleaned_data.get('enable_radio', False)
			broadcast.enable_youtube = form.cleaned_data.get('enable_youtube', False)
			broadcast.save()
			# Attach selected stations if provided
			station_ids = request.POST.getlist('stations')
			if station_ids:
				qs = Station.objects.filter(user=request.user, pk__in=station_ids)
				broadcast.stations.set(qs)
			return redirect('broadcasts:broadcast_list')
	else:
		initial = {}
		if request.GET.get('now'):
			initial['go_live_now'] = True
		form = BroadcastForm(initial=initial)
	user_stations = Station.objects.filter(user=request.user, enabled=True).order_by('name')
	return render(request, 'broadcasts/create.html', {"form": form, "user_stations": user_stations})


@login_required
def broadcast_studio(request, pk: int):
	"""Simple studio page for a broadcast with local preview and live toggle.

	For MVP: hosts can preview camera/mic and mark broadcast live/ended.
	Later we can integrate WebRTC (e.g., LiveKit) for multi-guest and RTMP egress.
	"""
	broadcast = get_object_or_404(Broadcast, pk=pk, user=request.user)

	if request.method == 'POST':
		action = request.POST.get('action')
		if action == 'go_live':
			broadcast.is_live = True
			broadcast.start_time = timezone.now()
			broadcast.save(update_fields=['is_live', 'start_time', 'updated_at'])
		elif action == 'end_live':
			broadcast.is_live = False
			broadcast.save(update_fields=['is_live', 'updated_at'])
		elif action == 'attach_station':
			try:
				sid = int(request.POST.get('station_id', ''))
				st = Station.objects.get(pk=sid, user=request.user, enabled=True)
				broadcast.stations.add(st)
			except Exception:
				pass
		elif action == 'detach_station':
			try:
				sid = int(request.POST.get('station_id', ''))
				st = Station.objects.get(pk=sid, user=request.user)
				broadcast.stations.remove(st)
			except Exception:
				pass
		return redirect('broadcasts:broadcast_studio', pk=broadcast.pk)

	# Provide user's enabled stations for selection if none attached
	user_stations = Station.objects.filter(user=request.user, enabled=True).order_by('name')
	context = {
		'broadcast': broadcast,
		'user_stations': user_stations,
	}
	return render(request, 'broadcasts/studio.html', context)
