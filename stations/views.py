
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Station

@login_required
def station_list(request):
	stations = Station.objects.filter(user=request.user)
	return render(request, 'stations/list.html', {'stations': stations})

@login_required
def station_create(request):
	if request.method == 'POST':
		# TODO: Add form handling logic
		pass
	return render(request, 'stations/create.html')
