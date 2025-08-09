
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Station
from .forms import StationForm
from django.http import JsonResponse, HttpResponseBadRequest
from django.utils import timezone
from urllib.parse import urlparse
import base64
import socket
import ssl
try:
	import requests
except Exception:
	requests = None

@login_required
def station_list(request):
	# Filter by user_id to avoid issues if request.user is a proxy or lazy object
	stations = Station.objects.filter(user_id=request.user.id)
	return render(request, 'stations/list.html', {'stations': stations})

@login_required
def station_create(request):
	if request.method == 'POST':
		form = StationForm(request.POST)
		if form.is_valid():
			station = form.save(commit=False)
			station.user = request.user
			station.save()
			messages.success(request, 'Station created successfully.')
			return redirect('stations:station_list')
	else:
		form = StationForm()
	return render(request, 'stations/create.html', { 'form': form })


@login_required
def station_test(request):
	"""Quickly test a stream URL reaches and returns a 200/401/302 etc.
	Accepts either posted form fields or a station id query param.
	"""
	if request.method not in ['POST', 'GET']:
		return HttpResponseBadRequest('Unsupported method')

	stream_url = None
	station = None
	basic_auth = None
	if 'id' in request.GET:
		station = Station.objects.filter(id=request.GET.get('id'), user_id=request.user.id).first()
		if station:
			stream_url = station.build_stream_url()
			if station.username and station.password:
				basic_auth = (station.username, station.password)
	else:
		# Build a temp Station from submitted fields (without saving)
		form = StationForm(request.POST or None)
		if form.is_valid():
			temp = form.save(commit=False)
			stream_url = temp.build_stream_url()
			if getattr(temp, 'username', None) and getattr(temp, 'password', None):
				basic_auth = (temp.username, temp.password)
		else:
			return JsonResponse({'ok': False, 'error': 'Invalid data', 'details': form.errors}, status=400)

	if not stream_url:
		return JsonResponse({'ok': False, 'error': 'Missing stream URL/host'}, status=400)

	common_headers = {
		'Icy-MetaData': '1',
		'User-Agent': 'PerspectiveStream/1.0 (+https://techopolis.app)'
	}

	if requests is not None:
		try:
			# Try HEAD first, then GET small range
			r = requests.head(stream_url, timeout=5, allow_redirects=True, auth=basic_auth, headers=common_headers)
			status = r.status_code
			if status >= 400:
				# Some servers don't support HEAD; try GET with small range
				hdrs = {'Range': 'bytes=0-1', **common_headers}
				r = requests.get(stream_url, timeout=8, stream=True, headers=hdrs, auth=basic_auth)
				status = r.status_code
			content_type = r.headers.get('Content-Type', '')
			result = {
				'ok': status < 400,
				'status': status,
				'content_type': content_type,
				'final_url': r.url,
			}
			if station:
				station.last_tested_at = timezone.now()
				if status == 401:
					station.connection_status = 'unauthorized'
				elif status < 400:
					station.connection_status = 'ok'
				else:
					station.connection_status = 'error'
				station.save(update_fields=['last_tested_at', 'connection_status'])
			return JsonResponse(result)
		except requests.exceptions.SSLError as e:
			# Retry once with verify=False; note insecure
			try:
				hdrs = {'Range': 'bytes=0-1', **common_headers}
				r = requests.get(stream_url, timeout=8, stream=True, headers=hdrs, auth=basic_auth, verify=False)
				status = r.status_code
				content_type = r.headers.get('Content-Type', '')
				result = {
					'ok': status < 400,
					'status': status,
					'content_type': content_type,
					'final_url': r.url,
					'insecure_tls': True,
				}
				if station:
					station.last_tested_at = timezone.now()
					station.connection_status = 'ok' if status < 400 else 'error'
					station.save(update_fields=['last_tested_at', 'connection_status'])
				return JsonResponse(result)
			except Exception as e2:
				# Fall through to raw socket
				last_err = f"SSL retry failed: {e2}"
		except Exception as e:
			# Fall through to raw socket attempt
			last_err = str(e)
	else:
		# Fallback using urllib
		import urllib.request
		import urllib.error
		try:
			password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
			if basic_auth:
				# Only add host; credentials will be sent on challenge
				password_mgr.add_password(None, stream_url, basic_auth[0], basic_auth[1])
			handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
			opener = urllib.request.build_opener(handler)
			req = urllib.request.Request(stream_url, method='HEAD', headers=common_headers)
			with opener.open(req, timeout=5) as resp:
				status = resp.status
				content_type = resp.headers.get('Content-Type', '')
		except Exception:
			try:
				req = urllib.request.Request(stream_url, headers={'Range': 'bytes=0-1', **common_headers})
				with opener.open(req, timeout=8) as resp:
					status = resp.status
					content_type = resp.headers.get('Content-Type', '')
			except Exception as e:
				last_err = str(e)

		result = {
			'ok': status < 400,
			'status': status,
			'content_type': content_type,
			'final_url': stream_url,
		}
		if station:
			station.last_tested_at = timezone.now()
			if status == 401:
				station.connection_status = 'unauthorized'
			elif status < 400:
				station.connection_status = 'ok'
			else:
				station.connection_status = 'error'
			station.save(update_fields=['last_tested_at', 'connection_status'])
		return JsonResponse(result)

	# Raw socket fallback (handle Shoutcast ICY 200 OK and some strict servers)
	try:
		parsed = urlparse(stream_url)
		scheme = parsed.scheme or 'http'
		host = parsed.hostname
		port = parsed.port or (443 if scheme == 'https' else 80)
		path = parsed.path or '/'
		if parsed.query:
			path = f"{path}?{parsed.query}"

		# Build request headers
		lines = [
			f"GET {path} HTTP/1.0",
			f"Host: {host}",
			"Icy-MetaData: 1",
			"User-Agent: PerspectiveStream/1.0 (+https://techopolis.app)",
			"Range: bytes=0-1",
			"Connection: close",
		]
		if basic_auth:
			token = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode()
			lines.append(f"Authorization: Basic {token}")
		lines.append("")
		lines.append("")
		req_bytes = "\r\n".join(lines).encode()

		sock = socket.create_connection((host, port), timeout=6)
		try:
			if scheme == 'https':
				context = ssl.create_default_context()
				try:
					sock = context.wrap_socket(sock, server_hostname=host)
				except ssl.SSLError:
					# Try insecure as last resort
					context = ssl._create_unverified_context()
					sock = context.wrap_socket(sock, server_hostname=host)
			sock.sendall(req_bytes)
			first_line = sock.recv(512)
		finally:
			try:
				sock.close()
			except Exception:
				pass

		# Check for ICY or HTTP 200
		line_up = first_line.upper()
		ok = line_up.startswith(b"ICY ") and b"200" in line_up or line_up.startswith(b"HTTP/1.") and b" 2" in line_up[:12]
		status = 200 if ok else 500
		result = {
			'ok': ok,
			'status': status,
			'content_type': None,
			'final_url': stream_url,
			'detected_protocol': 'ICY' if line_up.startswith(b'ICY ') else 'HTTP',
		}
		if station:
			station.last_tested_at = timezone.now()
			station.connection_status = 'ok' if ok else 'error'
			station.save(update_fields=['last_tested_at', 'connection_status'])
		return JsonResponse(result, status=200 if ok else 502)
	except Exception as e:
		if station:
			station.last_tested_at = timezone.now()
			station.connection_status = 'unreachable'
			station.save(update_fields=['last_tested_at', 'connection_status'])
		detail = str(e)
		if 'last_err' in locals():
			detail = f"{last_err} | fallback: {detail}"
		return JsonResponse({'ok': False, 'error': 'unreachable', 'details': detail}, status=502)
