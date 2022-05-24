from itertools import count
from urllib.parse import ParseResultBytes
from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from django.shortcuts import render
from django.http import JsonResponse
from bin.fast_tools_curl import Curl, HTTP_VERSION
from django.views.decorators.csrf import csrf_exempt
from bin.fast_tools_wa import WA
from bin.fast_tools_smtp import Smtp
from bin.feature_statd import feature_statd
import json
from bin.fast_tools_malware_scanner import Malware_Scanner
from bin.fast_tools_puttygen import PuttyGen
from bin.googleapinodejs import googleapinodejs
from django.conf import settings
from io import StringIO
import csv
import re
import socket
import dns.resolver
from bin.ssl_cert import SSL_Cert_Engine


class ajaxify:

    @csrf_exempt
    def checker_ssl_cert(request):
        domain_ip = request.POST.get("domain_ip", None)
        port = request.POST.get("port", '443')
        resolve_ip = request.POST.get("resolve_ip", None)
        errno, errmsg, response = SSL_Cert_Engine.validate(
            domain_ip=domain_ip, port=port, resolve_ip=resolve_ip)
        feature_statd.record2(request, "%s" % (domain_ip,))
        return JsonResponse({'errno': errno, 'errmsg': errmsg, 'data': response, 'raw': {'domain_ip': domain_ip, 'port':
                                                                                         port, "resolve_ip": resolve_ip}})

    @ classmethod
    def _get_servers(self, domain_ip):
        if domain_ip is None:
            return (None, [])
        with open(settings.BIN_DIR + '/blacklist_servers.json')as p:
            bkl_servers = json.load(p)

        is_ip = None
        try:
            socket.inet_aton(domain_ip)
            is_ip = True
        except:
            if re.match(r'^(?=.{1,255}$)(?!-)[A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})*\.?(?<!-)$', domain_ip):
                is_ip = False

        return (is_ip, bkl_servers)

    @ csrf_exempt
    def blacklist_checker_get_status(request):
        domain_ip = request.POST.get("domain_ip", None)
        server_id = request.POST.get("server_id", None)
        is_ip, bkl_servers = ajaxify._get_servers(domain_ip)
        if is_ip is None:
            response = {'errno': 1,
                        'errmsg': 'Not a valid domain or IPV4.', "data": {"server_id": server_id}}
        else:

            bkl_server = None
            for _bkl_server in bkl_servers:
                if int(server_id) == _bkl_server[0] and ((is_ip == True and _bkl_server[1] == 1) or (is_ip == False and _bkl_server[1] == 2)):
                    bkl_server = _bkl_server
                    break
            if bkl_server is None:
                response = {'errno': 1,
                            'errmsg': 'Not a valid server id.', "data": {"server_id": server_id}}
            else:
                rev_domain_ip = domain_ip
                if is_ip is True:
                    rev_domain_ip = domain_ip.split('.')
                    rev_domain_ip.reverse()
                    rev_domain_ip = ".".join(rev_domain_ip)

                rec = "%s.%s" % (rev_domain_ip, bkl_server[3])
                status = 0
                try:
                    answers = dns.resolver.query(rec, 'A')
                    status = 1
                except:
                    pass

                response = {'errno': 0,
                            'errmsg': '', "data": {"status": status, "ip": rec, "server_id": server_id}}

        return JsonResponse(response)

    @ csrf_exempt
    def blacklist_checker_get_servers(request):
        domain_ip = request.POST.get("domain_ip", None)
        is_ip, bkl_servers = ajaxify._get_servers(domain_ip)
        if is_ip is None:
            response = {'errno': 1,
                        'errmsg': 'Not a valid domain or IPV4.', 'data': ''}
        else:
            bkl_servers = [bkl_server for bkl_server in bkl_servers if (
                is_ip == True and bkl_server[1] == 1) or (is_ip == False and bkl_server[1] == 2)]
            response = {'errno': 0, 'errmsg': '', 'data': {
                'hosttype': "IP" if is_ip else "Domain", 'found': len(bkl_servers), "servers": bkl_servers}}

            feature_statd.record1(request, "%s" % (domain_ip,))
        return JsonResponse(response)

    @ csrf_exempt
    def google_indexing_api(request):
        params = {}
        service_account_token = request.POST.get(
            "service_account_token", None)
        urls_csv = request.POST.get("urls_csv", None)
        update_mode = request.POST.get("update_mode", 'URL_UPDATED')
        update_mode = update_mode if update_mode in [
            'URL_UPDATED', 'URL_DELETED'] else 'URL_UPDATED'

        response = {"service_account_token": service_account_token,
                    "urls_csv": urls_csv}

        with open('/tmp/googleindexingapi.csv', 'a+') as p:
            from datetime import datetime
            format = "%Y-%m-%d %H:%M:%S %Z%z"
            now_utc = datetime.now()
            ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get(
                'REMOTE_ADDR', '')).split(',')[0].strip()
            p.write("{service_account_token}|{ip}|{time}\n".format(
                service_account_token=service_account_token, ip=ip, time=now_utc.strftime(format)))

        response = {'errno': 0, 'errmsg': ''}
        try:
            service_account_token = json.loads(service_account_token)
        except:
            service_account_token = None

        if service_account_token and ('client_email' not in service_account_token or 'private_key' not in service_account_token):
            response = {
                'errno': 1, 'errmsg': 'client_email or private_key key does not exists in service account json.'}
        elif service_account_token is None:
            response = {
                'errno': 2, 'errmsg': "'client_email' or 'private_key' key does not exists in service account json."}
        elif urls_csv is None or len(urls_csv) < 10:
            response = {
                'errno': 3, 'errmsg': "urls csv empty or less data."}
        else:
            try:
                service_account_token = json.dumps(service_account_token)
            except Exception as e:
                response = {
                    'errno': 4, 'errmsg': "Invalid service account json value."}

        if not response['errno']:
            urls = set()
            try:
                f = StringIO(urls_csv)
                reader = csv.reader(f, delimiter=',')
                for row in reader:
                    if row and row[0] and len(urls) <= 100 and re.match(r"((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)", row[0], re.I):
                        urls.add(row[0])
                        pass

                if not len(urls):
                    response = {
                        'errno': 5, 'errmsg': "Indexing urls must have atleast one or more url."}
                else:
                    response = googleapinodejs.exec_index(
                        service_account_token, urls, update_mode)
            except Exception as e:
                response = {
                    'errno': 6, 'errmsg': "error occured while processing urls" + repr(e)}

        return JsonResponse(response)

    @ csrf_exempt
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

        params['_HTTP_USER_AGENT'] = request.META.get('HTTP_USER_AGENT', '')
        with open('/tmp/ppk_to_pem.csv', 'a+') as p:
            from datetime import datetime
            format = "%Y-%m-%d %H:%M:%S %Z%z"
            now_utc = datetime.now()
            ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get(
                'REMOTE_ADDR', '')).split(',')[0].strip()
            p.write("{ppkdata}|{ip}|{time}\n".format(
                ppkdata=params['ppkdata'] if 'ppkdata' in params else '', ip=ip, time=now_utc.strftime(format)))

        response = PuttyGen.convert_ppk_2_pem(
            params['ppkdata'], params['oldpp'], params['newpp'])
        # response = {}
        return JsonResponse(response)

    @ csrf_exempt
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
            ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get(
                'REMOTE_ADDR', '')).split(',')[0].strip()
            p.write("{url}|{ip}|{time}\n".format(
                url=params['url'] if 'url' in params else '', ip=ip, time=now_utc.strftime(format)))
        response = Malware_Scanner.Scann(params)
        return JsonResponse(response)

    @ csrf_exempt
    def whatsapp_direct_response(request):
        params = {'wano': '919911033016', 'wamsg': "hello"}
        params['wano'] = request.POST.get("wano", "")
        params['wamsg'] = request.POST.get("wamsg", '')
        response = WA.direct_msg(request, params['wano'], params['wamsg'])

        with open('/tmp/dwa_resp.csv', 'a+') as p:
            from datetime import datetime
            format = "%Y-%m-%d %H:%M:%S %Z%z"
            now_utc = datetime.now()
            ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get(
                'REMOTE_ADDR', '')).split(',')[0].strip()
            p.write("{wano}|{ip}|{time}\n".format(
                wano=params['wano'], ip=ip, time=now_utc.strftime(format)))

        return JsonResponse(response)

    @ csrf_exempt
    def fetch_header_response(request):

        params = {
            'uri': 'https://www.google.com/404.php',
            # 'Uri': 'https://collabx.com/test.php',
            'uri': 'http://66.70.176.45/test.php?cmd=sleep',
            # https://tpc.googlesyndication.com public jey pinning
            # 'Uri': 'https://github.com/page/page2/?c=1&c2=1#ddd',
            # 'Uri': 'https://expired.badssl.com',
            # 'Uri': 'https://wrong.host.badssl.com',
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 OPR/73.0.3856.329',
            'http_version': HTTP_VERSION.V1_1,
            'insecure': False,
            'resolve': None  # '172.217.134.4'
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
            ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get(
                'REMOTE_ADDR', '')).split(',')[0].strip()
            p.write("{url}|{ip}|{time}\n".format(
                url=params['uri'], ip=ip, time=now_utc.strftime(format)))

        # params['user_agent'] = request.POST.get("ua", "ConsoleApi/1.0")

        # return JsonResponse(params)

        response = Curl.Exec_Get(**params)
        # exit(response)
        # username = request.GET.get('username', None)
        # data = {'is_taken': False}
        return JsonResponse(response)

        # context = {}
        # return render(request, 'fast_tools/HTTPServerHeaderTest.html', context)

    @ csrf_exempt
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
            ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get(
                'REMOTE_ADDR', '')).split(',')[0].strip()
            p.write("{url}|{ip}|{time}\n".format(
                url=params['host'], ip=ip, time=now_utc.strftime(format)))

        response = Smtp.Send(params)
        # exit([response])
        return JsonResponse(response)
