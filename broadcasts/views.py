
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Broadcast

@login_required
def broadcast_list(request):
	broadcasts = Broadcast.objects.filter(user=request.user).order_by('-start_time')
	return render(request, 'broadcasts/list.html', {'broadcasts': broadcasts})

@login_required
def broadcast_create(request):
	if request.method == 'POST':
		# TODO: Add form handling logic
		pass
	return render(request, 'broadcasts/create.html')
