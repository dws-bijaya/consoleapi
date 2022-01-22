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
from bin.fast_tools_puttygen import PuttyGen
from django.conf import settings


class ajaxify:
	@csrf_exempt
	def convert_ppk_to_pem(request):
		params = {
		    'ppkdata': '''
PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: imported-openssh-key
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCEZoVdt1wr6k6KTLWgtJX6sOE0ruZPgtoc
98IbusJYmnRHTssD4GqhYMxpuajG9Oon0MVUwByKO+BUESM7qHeGdqXW5v6gd7jx
7i40DlzDZnjWle5HEDmoKyktUp7U2avXDZv3UBsaHsYwgcF4KxHGddMZ6Np2f4gp
02YAdCBzjfNbXoxWqhfmmiY47gPL3W4L02g7iibHZp6aeVyloD62yOsuQDfUR1v1
IOp6/iHGxzf+NdmHSM1dPqQlb1PTZH0YQM2ACOK9ERdw3LRoQqRRb2E0XECVjObO
oZriQG59dd/mQZ3KATDfF2S1LR/PkZKSrdRV57SaKaUaTa/QSZQJ
Private-Lines: 14
AAABABOJqW6N600Ts2lXLoo7e9JVnbYPhS8AiT0zFnLPGXTHvhbzuqOkzzdnOGL1
ocFSTOd5OFVsUAnaEh11tfRMxO6TvZ870SFO6XzSAAFwiSHQkk5gK5xS+Z8mV1o3
0fZo9KG0gWp6aLVvCyIHU8xu1p2pr3AoW2yXHznE102D1XIXrNSm5Tg2CMvPlh1G
E1X9CMEP33oPOnYfX1IMRdErsXgTvfrEEj07ESkr6SgCCSCAvrP7WaQOmTs0dSXJ
QfYbsAUal/9vU+8XCv3lgSeF4+ZP+93AMlMCncmXQxVT4BIf3GI3SA9Eh+Mxu/ub
3719MKFNUdXik6YIan6G4mwqHAEAAACBAPVhzP8L1PLv2RJxPo0Cnd5LOCnmn75n
Tr+iIXwXh7hVjZ7AQXswMoJBa+NXjlIpedDtfDvP2pFPXJW8TF6EmiLz0D/F4ijs
48ITKB9cU0Q6EJiwtMT6/P1/SAXBN3Ncujx89Ei3cGTlJpmhEKWgK1dCxUFDxnES
Vke5io27NAeJAAAAgQCKIS0f8DCFj22d1FVeD4TKK8wD2/pbGqocZd028b7Fi6Hl
8oiSGB8p5whFKXDJbreLoP1xymCe9GZZNgKyZ/k6iqds0rUn68luHjBHgzz6ES3c
PfsuiqDU5ToQd8E7+0dJCaUnyvI7ZkvE4BLA04wU+CHhXcXYfhvvGgxn6UmIgQAA
AIEAtoAxkjYIgicv7jTk/JdlRDBz8dinixugBIRe1gEjR4mFse2tld9Nok84T7pE
vE11UtN55xGpgYRRxmbC2EDt3SuZTnyQvlHlUWwUwzutcNk0be6gsOUkh8OalupU
uoaLsyXf9U+eyulgcnoS7i6NC9Bx/TXUFHfYJlAKFVqPemI=
Private-MAC: ac2e87434317d6ee04b359c38903e40d8315a547
		''',
		    'oldpp': None,
		    'newpp': "LAxmi"
		}
		params['ppkdata'] = request.POST.get("ppkdata", "")
		params['oldpp'] = request.POST.get("oldpp", "")
		params['newpp'] = request.POST.get("newpp", '')
		response = PuttyGen.convert_ppk_2_pem(params['ppkdata'], params['oldpp'], params['newpp'])
		#response = {}
		return JsonResponse(response)

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
