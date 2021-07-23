from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from django.shortcuts import render
from django.http import JsonResponse
from bin.fast_tools_curl import Curl, HTTP_VERSION
from django.views.decorators.csrf import csrf_exempt
from bin.fast_tools_wa import WA
from bin.fast_tools_smtp import Smtp
import json
from bin.fast_tools_malware_scanner import Malware_Scanner


class ajaxify:
	@csrf_exempt
	def webpage_malware_scanner_response(request):
		try:
			params = json.loads(request.body.decode("utf-8"))
		except:
			params = {}
			pass

		params['_HTTP_USER_AGENT'] = request.META.get('HTTP_USER_AGENT', '')
		with open('/tmp/wscan_resp.csv', 'a+') as p:
			from datetime import datetime
			format = "%Y-%m-%d %H:%M:%S %Z%z"
			now_utc = datetime.now()
			ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
			p.write("{url}|{ip}|{time}\n".format(url=params['url'] if 'url' in params else '', ip=ip, time=now_utc.strftime(format)))
		response = Malware_Scanner.Scann(params)
		return JsonResponse(response)

	@csrf_exempt
	def whatsapp_direct_response(request):
		params = {'wano': '919911033016', 'wamsg': "hello"}
		params['wano'] = request.POST.get("wano", "")
		params['wamsg'] = request.POST.get("wamsg", '')
		response = WA.direct_msg(request, params['wano'], params['wamsg'])

		with open('/tmp/dwa_resp.csv', 'a+') as p:
			from datetime import datetime
			format = "%Y-%m-%d %H:%M:%S %Z%z"
			now_utc = datetime.now()
			ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
			p.write("{wano}|{ip}|{time}\n".format(wano=params['wano'], ip=ip, time=now_utc.strftime(format)))

		return JsonResponse(response)

	@csrf_exempt
	def fetch_header_response(request):

		params = {
		    'uri': 'https://www.google.com/404.php',
		    #'Uri': 'https://collabx.com/test.php',
		    'uri': 'http://66.70.176.45/test.php?cmd=sleep',
		    # https://tpc.googlesyndication.com public jey pinning
		    # 'Uri': 'https://github.com/page/page2/?c=1&c2=1#ddd',
		    #'Uri': 'https://expired.badssl.com',
		    # 'Uri': 'https://wrong.host.badssl.com',
		    'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 OPR/73.0.3856.329',
		    'http_version': HTTP_VERSION.V1_1,
		    'insecure': False,
		    'resolve': None  #'172.217.134.4'
		}

		insecure = request.POST.get("is", "false").lower()
		insecure = insecure == 'true' or insecure == 'on' or insecure == '1'
		params = {}
		params['user_agent'] = request.POST.get("url", "")
		params['uri'] = request.POST.get("url", "")
		params['insecure'] = insecure
		params['resolve'] = request.POST.get("ip", None)

		with open('/tmp/hdr_resp.csv', 'a+') as p:
			from datetime import datetime
			format = "%Y-%m-%d %H:%M:%S %Z%z"
			now_utc = datetime.now()
			ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
			p.write("{url}|{ip}|{time}\n".format(url=params['uri'], ip=ip, time=now_utc.strftime(format)))

		#params['user_agent'] = request.POST.get("ua", "ConsoleApi/1.0")

		#return JsonResponse(params)

		response = Curl.Exec_Get(**params)
		#exit(response)
		#username = request.GET.get('username', None)
		#data = {'is_taken': False}
		return JsonResponse(response)

		#context = {}
		#return render(request, 'fast_tools/HTTPServerHeaderTest.html', context)

	@csrf_exempt
	def email_smtp_response(request):
		'''
		from io import StringIO
		import os, sys
		old_stderr = sys.stderr
		redirected_error = sys.stderr = StringIO()
		print("hello", file=sys.stderr)
		return JsonResponse({"response": redirected_error.getvalue()})
		'''

		params = json.loads(request.body.decode("utf-8"))
		with open('/tmp/smtp_resp.csv', 'a+') as p:
			from datetime import datetime
			format = "%Y-%m-%d %H:%M:%S %Z%z"
			now_utc = datetime.now()
			ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
			p.write("{url}|{ip}|{time}\n".format(url=params['host'], ip=ip, time=now_utc.strftime(format)))

		response = Smtp.Send(params)
		#exit([response])
		return JsonResponse(response)
