import pycurl, time
import io
from io import BytesIO
import ssl
import urllib

import pycurl

import ssl
import socket
import OpenSSL
from pprint import pprint
from datetime import datetime
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
from datetime import datetime
import binascii
HTTP_VERSION_1_0 = 0x1
HTTP_VERSION_1_1 = 0x2
HTTP_VERSION_2_0 = 0x3
HTTP_METHOD_GET = 'GET'
HTTP_METHOD_POST = 'POST'

from urllib.parse import scheme_chars, urlparse, parse_qs, urlunparse, ParseResult
from easy_timezones.utils import is_valid_ip
import ipaddress
import http.server
from http.cookies import Morsel, SimpleCookie
import re


class FAST_TOOLS_CURL_ERROR:
	OK = (0x0, '+OK')
	UNKNONWN = (0x2, 'Unknown error.')


def parse_dict_cookies(value):
	result = {}
	for item in value.split(';'):
		item = item.strip()
		if not item:
			continue
		if '=' not in item:
			result[item] = None
			continue
		name, value = item.split('=', 1)
		result[name] = value
	return result


def _parse_response_headers(hfun_buffer: io.BytesIO, parent_domain: str, response: dict):
	headers_dict = []
	headers_str = hfun_buffer.getvalue().decode().strip()
	resp_msg = None
	res_headers = headers_str.splitlines()
	#exit([(res_headers)])
	Content_Type = None
	Strict_Transport_Security = None
	Content_Encoding = None
	Public_Key_Pins = None
	Cookies = []
	headers_str = []
	for header in res_headers:
		if not header:
			continue

		if not resp_msg and header.startswith('HTTP/'):
			resp_msg = header
			continue

		parts = header.split(':')
		key, val = parts[0].lower(), parts[1].strip() if len(parts) > 1 else None
		headers_dict.append([key.title(), val])
		headers_str.append(header)
		if not Content_Type and key == 'content-type'.lower():
			Content_Type = val

		if not Strict_Transport_Security and key == 'strict-transport-security':
			Strict_Transport_Security = val

		if not Public_Key_Pins and key == 'public-key-pins':
			m = re.findall(r'pin-sha256="(.[^"]*)"', val)
			if m:
				Public_Key_Pins = m

		if not Content_Encoding and key == 'content-encoding':
			Content_Encoding = val

		if 'set-cookie' == key:
			_cookie = Robotcookie(val, parent_domain)
			Cookies.append(_cookie)

	headers_str.insert(0, resp_msg)

	response['content_type'] = Content_Type
	response['strict_transport_security'] = Strict_Transport_Security
	response['content_encoding'] = Content_Encoding
	response['response_headers_raw'] = "\r\n".join(headers_str)
	response['response_headers_map'] = headers_dict
	response['response_cookies'] = Cookies
	response['public_key_pins'] = Public_Key_Pins

	#set-cookie: NID=207=AA-ov3QLhcoZsyCbF0n9dB1U0JN5KdG9ArNc4-7hZNWxH6lgWIlfpz5sq39Mn-NS5z4wxWNkXYbepF-Wu1YFTyp2VvcNf4k1TooEzDfWWaWWWuz-WSB8aj9ZAsVdLJ5--6sJRnvuai5z7zi0Favm-oJoQc1BdyMcdtiGe_33Vj4; expires=Sun, 25-Jul-2021 15:49:05 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=none
	#exit([Content_Type, Strict_Transport_Security, Content_Encoding, headers_dict, headers_str, Cookies, Public_Key_Pins, headers_str])
	#exit([headers])


def opensocket(curl, purpose, curl_address):
	exit([curl, purpose, help(curl_address)])


def _parse_url(Uri: str, response: dict):
	try:
		response['url'] = Uri
		uparts = urlparse(Uri)
		response['scheme'] = uparts.scheme if uparts.scheme else None
		response['host'] = uparts.hostname if uparts.hostname else None
		response['port'] = int(uparts.port) if uparts.port else None
		response['username'] = uparts.username if uparts.username else None
		response['password'] = uparts.password if uparts.password else None
		response['query'] = uparts.query if uparts.query else None
		response['params'] = parse_qs(uparts.query) if uparts.query else None
		response['fragment'] = uparts.fragment if uparts.fragment else None
		response['filename'] = uparts.path if uparts.path else None
		response['request_uri'] = (uparts.path + '?{qrystr}'.format(qrystr=uparts.query) if uparts.query else '/') + "" + ('#{fragment}'.format(fragment=uparts.fragment) if uparts.fragment else '')
		netloc = '{domain}{port}'.format(domain=response['host'], port=':{}'.format(response['port']) if response['port'] else '')
		Uri = ParseResult(scheme=response['scheme'], netloc=netloc, path=response['filename'] if response['filename'] else '', params={}, query=response['query'], fragment=response['fragment']).geturl()
		response['url'] = Uri
		#exit(response)
	except Exception as e:
		#raise e
		response['errno'], response['errmsg'] = 1, 'Mailform URL'


def _parse_request_headers(method: HTTP_METHOD_GET, request_headers: io.BytesIO, response: dict, httpheaders: list, parent_domain: str):
	headers = request_headers.getvalue().decode()
	if (headers):
		_headers = ["{} {} {}".format(method, response['request_uri'], response['version'])]
		_headers += httpheaders
		headers = "\r\n".join(_headers)

	exit([headers])
	first_header = ''
	headers_dict = []
	Cookies = []
	headers_str = []
	for header in headers.splitlines():
		if not header:
			continue

		#
		if not first_header and header.startswith('GET '):
			first_header = header
			continue

		parts = header.split(':')
		key, val = parts[0].lower(), parts[1].strip() if len(parts) > 1 else None
		headers_dict.append([key.title(), val])
		headers_str.append(header)

		#key = 'cookie'
		#val = '1P_JAR=2021-01-24-14; NID=207=U-LdcEtfcxoxNmkvXCJrwXqc1drpixiaGHHp-ZCy5IVH9qukOm3QX-CjWn9LvYz4X-WJmV7raNmsjAnIBVXuHF6P-ZtKn6Pwb2c8bTL6ag3dL4lD4rY2_adAvrqf7gwlwBZrdpAIZMIQf0dxFxm5M_2Tql5GtiMdIyFG-hxMibA; ANID=AHWqTUnz3F_su4GrWPILxNyeXbQ0rRbYoImohr6chMQ1Fcnck9ErlB-P3tjK033c; DV=Q-9FXVSTyekhgNhQRBDdE3Fo559Lc5c3wvMubcWccwEAAAA'
		#val = 'r=1nEbfGqifzgWhR3fo..BgDX9-.Fv.AAA.0.0.BgDX9-.AWVYg20DBlE; expires=Sat, 24-Apr-2021 14:09:01 GMT; Max-Age=7775999; path=/; domain=.facebook.com; secure; httponly; SameSite=None'
		if 'cookie' == key:
			try:
				for CookieName, v in SimpleCookie(val).items():
					CookieValue = v.value
					Domain = v.get('domain', parent_domain)
					Path = v.get('Path', '/')
					Expires = v.get('Expires', None)
					Comment = v.get('Comment', None)
					MaxAge = v.get('MaxAge', None)
					SameSite = v.get('samesite', None)
					HttpOnly = v.get('HttpOnly', None)
					Secure = v.get('Secure', None)
					Version = v.get('Version', None)
					Priority = v.get('Priority', 'medium')
					Sessionkey = True if Expires is None else False
					Cookie = {
					    CookieName: CookieValue,
					    'Domain': Domain,
					    'Path': Path,
					    'Expires': Expires,
					    'Comment': Comment,
					    'MaxAge': MaxAge,
					    'SameSite': SameSite,
					    'HttpOnly': HttpOnly,
					    'Secure': Secure,
					    'Size': len(CookieValue),
					    'Sessionkey': Sessionkey,
					    'Version': Version,
					    'Priority': Priority
					}
					Cookies.append(Cookie)

			except Exception as e:
				pass

		#exit([Cookies])

	headers_str.insert(0, first_header)
	#exit(headers_dict)
	response['request_headers_raw'] = "\r\n".join(headers_str)
	response['request_headers_size'] = len(response['request_headers_raw'])
	response['request_headers_map'] = headers_dict
	response['request_cookies'] = Cookies
	exit([response])


def calculate_timmings(c, response, request_sent_time_ms):

	blocked_time_ms = 0
	dns_resolution_time_ms = 0
	connecting_time_ms = 0
	ssl_setup_time_ms = 0
	pretransfer_time_ms = 0
	sending_time_ms = 0
	redirct_time = 0
	waiting_time_ms = 0
	receive_time_ms = 0

	NAMELOOKUP_TIME = c.getinfo(c.NAMELOOKUP_TIME) * 1000
	CONNECT_TIME = c.getinfo(c.CONNECT_TIME) * 1000
	APPCONNECT_TIME = c.getinfo(c.APPCONNECT_TIME) * 1000
	PRETRANSFER_TIME = c.getinfo(c.PRETRANSFER_TIME) * 1000
	STARTTRANSFER_TIME = c.getinfo(c.STARTTRANSFER_TIME) * 1000
	TOTAL_TIME = c.getinfo(c.TOTAL_TIME) * 1000
	#exit([TOTAL_TIME])
	dns_resolution_time_ms = NAMELOOKUP_TIME
	connecting_time_ms = CONNECT_TIME - NAMELOOKUP_TIME
	ssl_setup_time_ms = APPCONNECT_TIME - CONNECT_TIME
	pretransfer_time_ms = PRETRANSFER_TIME - APPCONNECT_TIME

	#exit([request_sent_time_ms, 111])
	if request_sent_time_ms['start'] and request_sent_time_ms['end']:
		sending_time_ms = request_sent_time_ms['end'] - request_sent_time_ms['start']
	waiting_time_ms = STARTTRANSFER_TIME - PRETRANSFER_TIME - sending_time_ms
	receive_time_ms = TOTAL_TIME - STARTTRANSFER_TIME
	totaltime = sum([dns_resolution_time_ms, connecting_time_ms, ssl_setup_time_ms, pretransfer_time_ms, sending_time_ms, waiting_time_ms, receive_time_ms])

	#exit([sending_time_ms])
	"""
	print("dns_resolution_time_ms = %.15f ms" % (dns_resolution_time_ms))
	print("connecting_time_ms     = %.15f ms" % (connecting_time_ms))
	print("ssl_setup_time_ms     = %.15f ms" % (ssl_setup_time_ms))
	print("pretransfer_time_ms     = %.15f ms" % (pretransfer_time_ms))
	print("requesting_time_ms     = %.15f ms" % (sending_time_ms))
	print("waiting_time_ms     = %.15f ms" % (waiting_time_ms))
	print("receive_time_ms     = %.15f ms" % (receive_time_ms))

	print("total time     = %.15f ====== %.15f" % (TOTAL_TIME, totaltime))
	exit()
	#t1 = (c.getinfo(pycurl.CONNECT_TIME)) - c.getinfo(pycurl.NAMELOOKUP_TIME)
	#print([c.getinfo(pycurl.CONNECT_TIME), c.getinfo(pycurl.NAMELOOKUP_TIME), t1, '%.2f' % t1])
	#print('Port : %s %s' % (c.getinfo(pycurl.STARTTRANSFER_TIME), t1))
	#print('Port : %s === %2.5f, %2.5f, %2.5f, %2.5f, %2.5f, %2.5f, %2.5f' % (c.getinfo(pycurl.CONNECT_TIME) >= c.getinfo(pycurl.NAMELOOKUP_TIME), c.getinfo(pycurl.TOTAL_TIME), c.getinfo(pycurl.NAMELOOKUP_TIME), c.getinfo(
	#    pycurl.CONNECT_TIME), c.getinfo(pycurl.APPCONNECT_TIME), c.getinfo(pycurl.PRETRANSFER_TIME), c.getinfo(pycurl.STARTTRANSFER_TIME),
	#                                                                         (c.getinfo(pycurl.NAMELOOKUP_TIME) + c.getinfo(pycurl.CONNECT_TIME) + c.getinfo(pycurl.APPCONNECT_TIME) + c.getinfo(pycurl.PRETRANSFER_TIME))))
	#print(pycurl.CONNECT_TIME, pycurl.NAMELOOKUP_TIME, pycurl.APPCONNECT_TIME, pycurl.STARTTRANSFER_TIME, pycurl.TOTAL_TIME)
	exit()

	exit('timmings')
	"""

	response['blocked_time_ms'] = blocked_time_ms
	response['dns_resolution_time_ms'] = dns_resolution_time_ms
	response['connecting_time_ms'] = connecting_time_ms
	response['ssl_setup_time_ms'] = ssl_setup_time_ms
	response['pretransfer_time_ms'] = pretransfer_time_ms
	response['sending_time_ms'] = sending_time_ms
	response['redirct_time'] = redirct_time
	response['waiting_time_ms'] = waiting_time_ms
	response['receive_time_ms'] = receive_time_ms
	response['total_time_ms'] = totaltime


def analysis_security(c, response, hostname: str):
	certinfo = c.getinfo(c.INFO_CERTINFO)
	Signature_Algorithm = None
	Key_Exchange_Group = 'X509v3'
	Public_Key_Pinning = 'Disabled'
	#issue

	#exit([certinfo[1]])
	_Public_Key_Pinning = None
	Certificate_Issue_To_CN = None
	Certificate_Issue_To_O = None
	Certificate_Issue_To_OU = None
	Certificate_Issue_To_C = None
	Certificate_Issue_To_ST = None
	Certificate_Issue_To_L = None

	Certificate_Issue_By_CN = None
	Certificate_Issue_By_O = None
	Certificate_Issue_By_OU = None
	Certificate_Issue_By_C = None
	Certificate_Issue_By_ST = None
	Certificate_Issue_By_L = None

	Period_Of_Validity_Begins_On = None
	Period_Of_Validity_Expires_On = None

	Certificate_Public_Key = None
	Certificate_Serial_No = None
	Certificate_Signature_Algorithm = None
	Certificate_Expired = None
	Certificate_Secure = None
	Fingerprints_sha256 = Fingerprints_sha1 = Fingerprints_md5 = Public_Key_Pinning_bs64 = None

	if certinfo:
		for inf in certinfo[0]:
			if inf[0] == 'Signature Algorithm':
				Certificate_Signature_Algorithm = inf[1]
			if inf[0] == 'Cert':
				certb64 = inf[1]
				try:
					cert = crypto.load_certificate(crypto.FILETYPE_PEM, certb64)
					notBefore, notAfter = cert.get_notBefore(), cert.get_notAfter()
					try:
						if notBefore:
							notBefore = datetime.strptime(notBefore.decode(), '%Y%m%d%H%M%S%z').strftime('%d %b %Y')
						if notAfter:
							notAfter = datetime.strptime(notAfter.decode(), '%Y%m%d%H%M%S%z').strftime('%d %b %Y')
						Period_Of_Validity_Begins_On, Period_Of_Validity_Expires_On = notBefore, notAfter
					except Exception as e:
						notBefore = notAfter = None

					#exit(help(cert))
					subject = cert.get_subject()
					Certificate_Issue_To_CN = subject.CN
					Certificate_Issue_To_O = subject.O
					Certificate_Issue_To_OU = subject.OU
					Certificate_Issue_To_C = subject.C
					Certificate_Issue_To_ST = subject.ST
					Certificate_Issue_To_L = subject.L
					Certificate_Secure = subject.CN and subject.CN == hostname

					issuer = cert.get_issuer()

					Certificate_Issue_By_CN = issuer.CN
					Certificate_Issue_By_O = issuer.O
					Certificate_Issue_By_OU = issuer.OU

					Certificate_Issue_By_C = issuer.C
					Certificate_Issue_By_ST = issuer.ST
					Certificate_Issue_By_L = issuer.L

					Certificate_Public_Key = None  #help(cert.get_pubkey())
					Certificate_Serial_No = cert.get_serial_number()
					#Certificate_Signature_Algorithm = cert.get_signature_algorithm()
					Certificate_Expired = cert.has_expired()
					#elp(Certificate_Signature_Algorithm)
					#exit([Certificate_Public_Key, Certificate_Serial_No, Certificate_Signature_Algorithm, Certificate_Expired])

					Fingerprints_sha256 = cert.digest('sha256').decode()
					Fingerprints_sha1 = cert.digest('sha1').decode()
					Fingerprints_md5 = cert.digest('md5').decode()
					bsha256 = base64.b64encode(binascii.a2b_hex(Fingerprints_sha256.replace(':', '')))
					Public_Key_Pinning_bs64 = bsha256.decode()
				except Exception as e:
					print(e)
					pass

			#print(inf)

	response['ssl_cert_issued_to_cn'] = Certificate_Issue_To_CN
	response['ssl_cert_issued_to_o'] = Certificate_Issue_To_O
	response['ssl_cert_issued_to_ou'] = Certificate_Issue_To_OU
	response['ssl_cert_issued_to_u'] = Certificate_Issue_To_C
	response['ssl_cert_issued_to_l'] = Certificate_Issue_To_L
	response['ssl_cert_issued_to_st'] = Certificate_Issue_To_ST
	response['ssl_cert_issued_to_c'] = Certificate_Issue_To_C

	response['ssl_cert_issued_by_cn'] = Certificate_Issue_By_CN
	response['ssl_cert_issued_by_o'] = Certificate_Issue_By_O
	response['ssl_cert_issued_by_ou'] = Certificate_Issue_By_OU
	response['ssl_cert_issued_by_u'] = Certificate_Issue_By_C
	response['ssl_cert_issued_by_l'] = Certificate_Issue_By_L
	response['ssl_cert_issued_by_st'] = Certificate_Issue_By_ST
	response['ssl_cert_issued_by_c'] = Certificate_Issue_By_C

	response['ssl_cert_validity_begins_on'] = Period_Of_Validity_Begins_On
	response['ssl_cert_validity_expires_on'] = Period_Of_Validity_Expires_On

	response['ssl_cert_public_key'] = Certificate_Public_Key
	response['ssl_cert_serial_no'] = Certificate_Serial_No
	response['ssl_cert_signature_algorithm'] = Certificate_Signature_Algorithm

	response['ssl_cert_expired'] = Certificate_Expired
	response['ssl_secure'] = Certificate_Secure and not Certificate_Expired

	response['ssl_key_exchange_group'] = Key_Exchange_Group

	response['ssl_fingerprints_sha256'] = Fingerprints_sha256
	response['ssl_fingerprints_sha1'] = Fingerprints_sha1
	response['ssl_fingerprints_md5'] = Fingerprints_md5

	response['ssl_public_key_pinning_bs64'] = Public_Key_Pinning_bs64

	#exit(response)
	#exit([c.getinfo(c.SSL_ENGINES)])
	#exit("analysis_security")


def get_default_response(Uri: str):
	response = {}
	response['errno'], response['errmsg'] = FAST_TOOLS_CURL_ERROR.UNKNONWN
	response['url'] = Uri
	response['method'] = None
	response['scheme'] = None
	response['host'] = None
	response['port'] = None
	response['username'] = None
	response['password'] = None
	response['query'] = None
	response['params'] = None
	response['fragment'] = None
	response['filename'] = None
	response['version'] = None
	response['remote_addess'] = None
	response['status_code'] = None
	response['status_msg'] = None
	response['transferred'] = None
	response['referrer_policy'] = None

	response['blocked_time_ms'] = None
	response['dns_resolution_time_ms'] = None
	response['connecting_time_ms'] = None
	response['ssl_setup_time_ms'] = None
	response['pretransfer_time_ms'] = None
	response['sending_time_ms'] = None
	response['redirct_time'] = None
	response['waiting_time_ms'] = None
	response['receive_time_ms'] = None
	response['total_time_ms'] = None

	response['content_type'] = None
	response['strict_transport_security'] = None
	response['content_encoding'] = None
	response['response_headers_raw'] = None
	response['response_headers_map'] = None
	response['response_headers_size'] = None

	response['response_cookies'] = None
	response['public_key_pins'] = None

	response['request_headers_raw'] = None
	response['request_headers_map'] = None
	response['request_cookies'] = None
	response['request_headers_size'] = None

	return response


def get_default_headers(User_Agent: str = None):
	httpheaders = [
	    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8', 'Accept-Encoding: gzip, deflate',
	    'Cache-Control: max-age=0', 'Upgrade-Insecure-Requests: 1'
	]
	return httpheaders + ([User_Agent] if User_Agent else [])


def auto_build_uri_scheme(Uri: str):
	if Uri.lower().startswith('//'):
		Uri = 'http://{}'.format(Uri.strip("//"))
	elif not Uri.lower().startswith('http://') and not Uri.lower().startswith('https://'):
		Uri = f'http://{Uri}'
	return Uri


def Curl_Request_Exec(Uri: str, User_Agent: str, http_version=HTTP_VERSION_1_1, Insecure=False, Resolve=None):
	def debug_func(response: dict, debug_type, buffer, request_headers, request_sent_time_ms: dict):
		if debug_type == 0 and response['ssl_version'] is None:
			ssl_v = re.match(r'SSL connection using (.[^/]*) / (.*)', buffer.decode())
			if ssl_v:
				response['ssl_version'], response['ssl_cipher_suite'] = ssl_v.groups(0)
		if debug_type == 2:
			request_headers.write(buffer)
			if request_sent_time_ms['start'] is None:
				request_sent_time_ms['start'] = time.perf_counter() * 1000
				#exit([request_sending_start_time_ms])

		if request_sent_time_ms['start'] is not None and request_sent_time_ms['end'] is None:
			request_sent_time_ms['end'] = time.perf_counter() * 1000

		#print(debug_type, time.time(), buffer)

	#exit(Uri)
	httpheaders = get_default_headers(User_Agent)
	Uri = auto_build_uri_scheme(Uri)
	#exit([httpheaders, Uri])
	response = get_default_response(Uri)
	''' SSL data '''
	response['ssl_version'] = response['ssl_cipher_suite'] = None
	request_headers = io.BytesIO()
	_parse_url(Uri, response)
	if response['errno']:
		return response

	#
	if http_version not in [HTTP_VERSION_1_0, HTTP_VERSION_1_1, HTTP_VERSION_2_0]:
		response['errno'], response['errmsg'] = 2, 'Invalid HTTP version'
		return response
	#
	response['version'] = 'HTTP/1.1' if http_version == HTTP_VERSION_1_1 else 'HTTP/1.0' if http_version == HTTP_VERSION_1_0 else 'HTTP/2'
	response['remote_addess'] = None
	resolve_hosts = []
	if Resolve:
		if not isinstance(Resolve, str) or not is_valid_ip(Resolve) or not isinstance(ipaddress.ip_address(Resolve), ipaddress.IPv4Address):
			response['errno'], response['errmsg'] = 3, 'Invalid Resolve IP'
			return response

		resolve_hosts = ['{}:{}:{}'.format(response['host'], response['port'] if response['port'] else 80 if response['scheme'] else 443, Resolve)]
		response['remote_addess'] = Resolve
		if False:
			httpheaders.append('Host: %s' % response['host'])
			# rebuild URLs
			try:
				netloc = '{usrpwd}{domain}{port}'.format(usrpwd='{}:{}@'.format(response['username'] if response['username'] else '', response['password'] if response['password'] else '') if (response['username'] or response['username']) else '',
				                                         domain=response['remote_addess'],
				                                         port=':{}'.format(response['port']) if response['port'] else '')
				Uri = ParseResult(scheme=response['scheme'], netloc=netloc, path=response['filename'] if response['filename'] else '', params={}, query=response['query'], fragment=response['fragment']).geturl()
				#print(Uri, Uri.geturl(), netloc, response)
				#exit()
			except Exception as e:
				response['errno'], response['errmsg'] = 4, 'Mailform URL'
				raise e
				pass
		#response['port']

	#exit([Uri, httpheaders])
	wfun_buffer, hfun_buffer, http_buffer = io.BytesIO(), io.BytesIO(), io.BytesIO()
	request_sent_time_ms = {'start': None, 'end': None}

	def write_function(p, d):
		print(p)

	c = pycurl.Curl()
	c.setopt(c.URL, Uri)
	c.setopt(c.VERBOSE, True)  # to see request details
	c.setopt(pycurl.HEADERFUNCTION, hfun_buffer.write)
	#c.setopt(pycurl.WRITEHEADER, wfun_buffer.write)
	#c.setopt(pycurl.WRITEFUNCTION, wfun_buffer.write)
	c.setopt(pycurl.DEBUGFUNCTION, lambda d, b: debug_func(response, d, b, request_headers, request_sent_time_ms))
	c.setopt(pycurl.ACCEPT_ENCODING, 'gzip, deflate')
	c.setopt(pycurl.WRITEDATA, http_buffer)
	c.setopt(pycurl.USERAGENT, User_Agent)
	c.setopt(pycurl.OPT_CERTINFO, 1)
	c.setopt(pycurl.DNS_CACHE_TIMEOUT, 1)
	#c.setopt(pycurl.DNS_SERVERS, None)
	c.setopt(pycurl.FOLLOWLOCATION, False)
	c.setopt(pycurl.FAILONERROR, True)
	c.setopt(pycurl.HEADER, True)
	c.setopt(pycurl.IGNORE_CONTENT_LENGTH, True)
	c.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
	c.setopt(pycurl.CONNECTTIMEOUT, 5)
	c.setopt(pycurl.TCP_FASTOPEN, True)
	c.setopt(pycurl.TIMEOUT, 40)
	c.setopt(c.RESOLVE, resolve_hosts)
	c.setopt(pycurl.HTTP_VERSION, http_version)
	c.setopt(pycurl.NOSIGNAL, 1)
	c.setopt(pycurl.NOPROGRESS, 1)
	#c.setopt(c.OPENSOCKETFUNCTION, lambda purpose, address: opensocket(c, purpose, address))
	#exit([resolve_hosts])
	c.setopt(pycurl.HTTPHEADER, httpheaders)
	if Insecure:
		c.setopt(pycurl.SSL_VERIFYHOST, False)
		c.setopt(pycurl.SSL_VERIFYPEER, False)
	try:
		c.perform()
	except pycurl.error as exc:
		if exc.args[0] != pycurl.E_HTTP_RETURNED_ERROR:
			wfun_buffer.close(), hfun_buffer.close(), http_buffer.close()
			response['errno'], response['errmsg'] = tuple(exc.args)
			return response
		#print("Unable to reach %s (%s)" % (c., exc))
	#exit([request_headers])
	version = c.getinfo(pycurl.INFO_HTTP_VERSION)
	response['version'] = 'HTTP/1.1' if version == HTTP_VERSION_1_1 else 'HTTP/1.0' if version == HTTP_VERSION_1_0 else 'HTTP/2'

	response['status_code'] = c.getinfo(c.HTTP_CODE)
	response['status_msg'] = 'No Reason'
	if response['status_code'] in http.server.BaseHTTPRequestHandler.responses:
		response['status_msg'] = http.server.BaseHTTPRequestHandler.responses[response['status_code']][0]

	calculate_timmings(c, response, request_sent_time_ms)
	exit([response, 22])
	analysis_security(c, response, response['host'])
	#exit([request_headers])
	response['transferred'] = http_buffer.__sizeof__()
	response['transferred'] += hfun_buffer.__sizeof__()
	response['transferred'] = pycurl.SIZE_DOWNLOAD
	response['referrer_policy'] = 'no-referrer-when-downgrade'
	cookie_host = response['host']

	try:
		cookie_host = urlparse(c.getinfo(pycurl.EFFECTIVE_URL)).hostname
	except Exception as e:
		pass

	p(HTTP_METHOD_GET, request_headers, response, httpheaders, cookie_host)
	_parse_response_headers(hfun_buffer, cookie_host, response)
	response['ssl_public_key_pins'] = None
	if response['ssl_public_key_pinning_bs64'] and response['public_key_pins'].find(response['ssl_public_key_pinning_bs64']) >= 0:
		response['ssl_public_key_pins'] = True

	#exit(response)
	response['compression'] = 'no-referrer-when-downgrade'
	response['response_headers_size'] = c.getinfo(pycurl.HEADER_SIZE)

	#exit([response['transferred']])

	#c.getinfo(pycurl.SSL_ENGINES)
	exit()
	#exit([response])
	#exit([hfun_buffer.getvalue(), response])

	#exit([wfun_buffer.getvalue().decode()])
	#exit([hfun_buffer.getvalue().decode()])

	pycurl.HEADER
	pycurl.HEADER_SIZE
	#pycurl.CLOSESOCKETFUNCTION

	pycurl.WRITEHEADER
	pycurl.TCP_FASTOPEN
	pycurl.WRITEHEADER

	pycurl.RESOLVE
	pycurl.PRIMARY_IP
	pycurl.LOCAL_IP
	pycurl.PRIMARY_PORT


from bin.fast_tools_curl import Curl, HTTP_VERSION
params = {
    'uri': 'https://www.google.com/',
    #'Uri': 'https://collabx.com/test.php',
    # 'uri': 'http://66.70.176.45/test.php?cmd=sleep',
    # https://tpc.googlesyndication.com public jey pinning
    # 'Uri': 'https://github.com/page/page2/?c=1&c2=1#ddd',
    #'Uri': 'https://expired.badssl.com',
    # 'Uri': 'https://wrong.host.badssl.com',
    'uri': 'https://www.rankwatch.com',
    'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 OPR/73.0.3856.329',
    'http_version': HTTP_VERSION.V1_1,
    'insecure': False,
    'resolve': None  #'142.250.72.196'
}
params = {
    "uri": "https://expired.badssl.com",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 OPR/73.0.3856.329",
    "http_version": 2,
    "insecure": False,
    "resolve": ""
}
response = Curl.Exec_Get(**params)
import json
exit((response))

response = Curl_Request_Exec(**params)

ts = time.perf_counter()
c.perform()
certinfo = c.getinfo(c.INFO_CERTINFO)
print([certinfo])
exit()
'''

def encrypt_string(hash_string):
	sha_signature = hashlib.sha256(hash_string).hexdigest()
	return sha_signature


#cert = ssl.get_server_certificate(('www.google.com', 443), ssl_version=ssl.PROTOCOL_TLSv1_2)
#exit([cert])
cert = '-----BEGIN CERTIFICATE-----\nMIIFkzCCBHugAwIBAgIRAIaafcB6bfDlBQAAAACFkFYwDQYJKoZIhvcNAQELBQAw\nQjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET\nMBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMTAxMDUxMTU5NTVaFw0yMTAzMzAxMTU5\nNTRaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH\nEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRcwFQYDVQQDEw53\nd3cuZ29vZ2xlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMV\nxjwVVrYPVaprMwY5UIGmEtK6BQvztkpou10JDZiH4uCc1WKSAUJdGNtBDgEMEMLE\nhEAPQv1MySb5E/nq3QVpxoJCj2dAUbcPh2A/HiW766OtxEfFBOT93+M2uQtTQ2Lc\nm1+dvZPnxcbm6b6zrLk2bSY40qV2+8Sf+GYSTysZPZyikxy7xDtnVTudLrgWD951\nuaJNVWruJ4A/4ndMf5MY13zkF3RswbPUldd0tVLnljLiKcLKeTEcMOkAiKjhJ4t2\nWANri4u7sQxucHddtu+cnSEpgm07weXf/iPGUf1ylzSyFDMqii1DSr83hMFbB/mv\n/gA++iEMmlL7svo644kCAwEAAaOCAlwwggJYMA4GA1UdDwEB/wQEAwIFoDATBgNV\nHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRk4xbNybDR\nketdZjfmt9svGmlkezAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBo\nBggrBgEFBQcBAQRcMFowKwYIKwYBBQUHMAGGH2h0dHA6Ly9vY3NwLnBraS5nb29n\nL2d0czFvMWNvcmUwKwYIKwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZy9nc3IyL0dU\nUzFPMS5jcnQwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20wIQYDVR0gBBowGDAI\nBgZngQwBAgIwDAYKKwYBBAHWeQIFAzAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8v\nY3JsLnBraS5nb29nL0dUUzFPMWNvcmUuY3JsMIIBBAYKKwYBBAHWeQIEAgSB9QSB\n8gDwAHYA9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOMAAAF20qHtaAAA\nBAMARzBFAiEA6A2Cs3WN78XXIkGt2LYT2oCfEzghlmOIKEjIG6SM8E0CIHA5TTYT\nS/7Ra9HoAzRLAaRyUHNWbIeF0j6/MnYViUFJAHYARJRlLrDuzq/EQAfYqP4owNrm\ngr7YyzG1P9MzlrW2gagAAAF20qHtowAABAMARzBFAiEAsWevs/LqRTUSC5iynokF\npr/fzg1x5kL3gXOgMryxtCsCIF2l5uRuFteJ1rFaA1qpSqBIdtMYpJnqtfhompRG\nP4OGMA0GCSqGSIb3DQEBCwUAA4IBAQCIgcHDHWHLwRGl9bQxkgNGD3hS0Qwf5yKs\nLKkpTGOPQSGcAvdei5I60dhWDGvDhhKZOowpQt4KuOvgIqVVsPkzfwJ5POtE1DQM\n9Z2dB704oESkIslNHWaXyTzWfQF7arB8LiUUt5gWZXqM9/29aIYxM8k2/h3KBahl\nqEKeElnHZxYuDcSBXWku+rfPVm/QgPsSK8OvihaE5RB31GNbMr9ozPba1QUTAvCa\ns/0fnsCQSQHtspqG86LD/Ou0OPruLntSdc8I/7ENrftQBlOraL7nlKiWXZADGa2z\nsLx4/WD/4E0PoCN8vhPahNscJEzt8XCjX8veNqSmIkV4v3F7x3El\n-----END CERTIFICATE-----\n'
x = 'MIIFkzCCBHugAwIBAgIRAIaafcB6bfDlBQAAAACFkFYwDQYJKoZIhvcNAQELBQAw\nQjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET\nMBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMTAxMDUxMTU5NTVaFw0yMTAzMzAxMTU5\nNTRaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH\nEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRcwFQYDVQQDEw53\nd3cuZ29vZ2xlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMV\nxjwVVrYPVaprMwY5UIGmEtK6BQvztkpou10JDZiH4uCc1WKSAUJdGNtBDgEMEMLE\nhEAPQv1MySb5E/nq3QVpxoJCj2dAUbcPh2A/HiW766OtxEfFBOT93+M2uQtTQ2Lc\nm1+dvZPnxcbm6b6zrLk2bSY40qV2+8Sf+GYSTysZPZyikxy7xDtnVTudLrgWD951\nuaJNVWruJ4A/4ndMf5MY13zkF3RswbPUldd0tVLnljLiKcLKeTEcMOkAiKjhJ4t2\nWANri4u7sQxucHddtu+cnSEpgm07weXf/iPGUf1ylzSyFDMqii1DSr83hMFbB/mv\n/gA++iEMmlL7svo644kCAwEAAaOCAlwwggJYMA4GA1UdDwEB/wQEAwIFoDATBgNV\nHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRk4xbNybDR\nketdZjfmt9svGmlkezAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBo\nBggrBgEFBQcBAQRcMFowKwYIKwYBBQUHMAGGH2h0dHA6Ly9vY3NwLnBraS5nb29n\nL2d0czFvMWNvcmUwKwYIKwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZy9nc3IyL0dU\nUzFPMS5jcnQwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20wIQYDVR0gBBowGDAI\nBgZngQwBAgIwDAYKKwYBBAHWeQIFAzAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8v\nY3JsLnBraS5nb29nL0dUUzFPMWNvcmUuY3JsMIIBBAYKKwYBBAHWeQIEAgSB9QSB\n8gDwAHYA9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOMAAAF20qHtaAAA\nBAMARzBFAiEA6A2Cs3WN78XXIkGt2LYT2oCfEzghlmOIKEjIG6SM8E0CIHA5TTYT\nS/7Ra9HoAzRLAaRyUHNWbIeF0j6/MnYViUFJAHYARJRlLrDuzq/EQAfYqP4owNrm\ngr7YyzG1P9MzlrW2gagAAAF20qHtowAABAMARzBFAiEAsWevs/LqRTUSC5iynokF\npr/fzg1x5kL3gXOgMryxtCsCIF2l5uRuFteJ1rFaA1qpSqBIdtMYpJnqtfhompRG\nP4OGMA0GCSqGSIb3DQEBCwUAA4IBAQCIgcHDHWHLwRGl9bQxkgNGD3hS0Qwf5yKs\nLKkpTGOPQSGcAvdei5I60dhWDGvDhhKZOowpQt4KuOvgIqVVsPkzfwJ5POtE1DQM\n9Z2dB704oESkIslNHWaXyTzWfQF7arB8LiUUt5gWZXqM9/29aIYxM8k2/h3KBahl\nqEKeElnHZxYuDcSBXWku+rfPVm/QgPsSK8OvihaE5RB31GNbMr9ozPba1QUTAvCa\ns/0fnsCQSQHtspqG86LD/Ou0OPruLntSdc8I/7ENrftQBlOraL7nlKiWXZADGa2z\nsLx4/WD/4E0PoCN8vhPahNscJEzt8XCjX8veNqSmIkV4v3F7x3El'
#x = x.replace('\n', '')
xe = [
	b'0\x82\x05\x930\x82\x04{\xa0\x03\x02\x01\x02\x02\x11\x00\x86\x9a}\xc0zm\xf0\xe5\x05\x00\x00\x00\x00\x85\x90V0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000B1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x1e0\x1c\x06\x03U\x04\n\x13\x15Google Trust Services1\x130\x11\x06\x03U\x04\x03\x13\nGTS CA 1O10\x1e\x17\r210105115955Z\x17\r210330115954Z0h1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x130\x11\x06\x03U\x04\n\x13\nGoogle LLC1\x170\x15\x06\x03U\x04\x03\x13\x0ewww.google.com0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xa3\x15\xc6<\x15V\xb6\x0fU\xaak3\x069P\x81\xa6\x12\xd2\xba\x05\x0b\xf3\xb6Jh\xbb]\t\r\x98\x87\xe2\xe0\x9c\xd5b\x92\x01B]\x18\xdbA\x0e\x01\x0c\x10\xc2\xc4\x84@\x0fB\xfdL\xc9&\xf9\x13\xf9\xea\xdd\x05i\xc6\x82B\x8fg@Q\xb7\x0f\x87`?\x1e%\xbb\xeb\xa3\xad\xc4G\xc5\x04\xe4\xfd\xdf\xe36\xb9\x0bSCb\xdc\x9b_\x9d\xbd\x93\xe7\xc5\xc6\xe6\xe9\xbe\xb3\xac\xb96m&8\xd2\xa5v\xfb\xc4\x9f\xf8f\x12O+\x19=\x9c\xa2\x93\x1c\xbb\xc4;gU;\x9d.\xb8\x16\x0f\xdeu\xb9\xa2MUj\xee\'\x80?\xe2wL\x7f\x93\x18\xd7|\xe4\x17tl\xc1\xb3\xd4\x95\xd7t\xb5R\xe7\x962\xe2)\xc2\xcay1\x1c0\xe9\x00\x88\xa8\xe1\'\x8bvX\x03k\x8b\x8b\xbb\xb1\x0cnpw]\xb6\xef\x9c\x9d!)\x82m;\xc1\xe5\xdf\xfe#\xc6Q\xfdr\x974\xb2\x143*\x8a-CJ\xbf7\x84\xc1[\x07\xf9\xaf\xfe\x00>\xfa!\x0c\x9aR\xfb\xb2\xfa:\xe3\x89\x02\x03\x01\x00\x01\xa3\x82\x02\\0\x82\x02X0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa00\x13\x06\x03U\x1d%\x04\x0c0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x010\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14d\xe3\x16\xcd\xc9\xb0\xd1\x91\xeb]f7\xe6\xb7\xdb/\x1aid{0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\x98\xd1\xf8n\x10\xeb\xcf\x9b\xec`\x9f\x18\x90\x1b\xa0\xeb}\t\xfd+0h\x06\x08+\x06\x01\x05\x05\x07\x01\x01\x04\\0Z0+\x06\x08+\x06\x01\x05\x05\x070\x01\x86\x1fhttp://ocsp.pki.goog/gts1o1core0+\x06\x08+\x06\x01\x05\x05\x070\x02\x86\x1fhttp://pki.goog/gsr2/GTS1O1.crt0\x19\x06\x03U\x1d\x11\x04\x120\x10\x82\x0ewww.google.com0!\x06\x03U\x1d \x04\x1a0\x180\x08\x06\x06g\x81\x0c\x01\x02\x020\x0c\x06\n+\x06\x01\x04\x01\xd6y\x02\x05\x0303\x06\x03U\x1d\x1f\x04,0*0(\xa0&\xa0$\x86"http://crl.pki.goog/GTS1O1core.crl0\x82\x01\x04\x06\n+\x06\x01\x04\x01\xd6y\x02\x04\x02\x04\x81\xf5\x04\x81\xf2\x00\xf0\x00v\x00\xf6\\\x94/\xd1w0"\x14T\x18\x080\x94V\x8e\xe3M\x13\x193\xbf\xdf\x0c/ \x0b\xccN\xf1d\xe3\x00\x00\x01v\xd2\xa1\xedh\x00\x00\x04\x03\x00G0E\x02!\x00\xe8\r\x82\xb3u\x8d\xef\xc5\xd7"A\xad\xd8\xb6\x13\xda\x80\x9f\x138!\x96c\x88(H\xc8\x1b\xa4\x8c\xf0M\x02 p9M6\x13K\xfe\xd1k\xd1\xe8\x034K\x01\xa4rPsVl\x87\x85\xd2>\xbf2v\x15\x89AI\x00v\x00D\x94e.\xb0\xee\xce\xaf\xc4@\x07\xd8\xa8\xfe(\xc0\xda\xe6\x82\xbe\xd8\xcb1\xb5?\xd33\x96\xb5\xb6\x81\xa8\x00\x00\x01v\xd2\xa1\xed\xa3\x00\x00\x04\x03\x00G0E\x02!\x00\xb1g\xaf\xb3\xf2\xeaE5\x12\x0b\x98\xb2\x9e\x89\x05\xa6\xbf\xdf\xce\rq\xe6B\xf7\x81s\xa02\xbc\xb1\xb4+\x02 ]\xa5\xe6\xe4n\x16\xd7\x89\xd6\xb1Z\x03Z\xa9J\xa0Hv\xd3\x18\xa4\x99\xea\xb5\xf8h\x9a\x94F?\x83\x860\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x88\x81\xc1\xc3\x1da\xcb\xc1\x11\xa5\xf5\xb41\x92\x03F\x0fxR\xd1\x0c\x1f\xe7"\xac,\xa9)Lc\x8fA!\x9c\x02\xf7^\x8b\x92:\xd1\xd8V\x0ck\xc3\x86\x12\x99:\x8c)B\xde\n\xb8\xeb\xe0"\xa5U\xb0\xf93\x7f\x02y<\xebD\xd44\x0c\xf5\x9d\x9d\x07\xbd8\xa0D\xa4"\xc9M\x1df\x97\xc9<\xd6}\x01{j\xb0|.%\x14\xb7\x98\x16ez\x8c\xf7\xfd\xbdh\x8613\xc96\xfe\x1d\xca\x05\xa8e\xa8B\x9e\x12Y\xc7g\x16.\r\xc4\x81]i.\xfa\xb7\xcfVo\xd0\x80\xfb\x12+\xc3\xaf\x8a\x16\x84\xe5\x10w\xd4c[2\xbfh\xcc\xf6\xda\xd5\x05\x13\x02\xf0\x9a\xb3\xfd\x1f\x9e\xc0\x90I\x01\xed\xb2\x9a\x86\xf3\xa2\xc3\xfc\xeb\xb48\xfa\xee.{Ru\xcf\x08\xff\xb1\r\xad\xfbP\x06S\xabh\xbe\xe7\x94\xa8\x96]\x90\x03\x19\xad\xb3\xb0\xbcx\xfd`\xff\xe0M\x0f\xa0#|\xbe\x13\xda\x84\xdb\x1c$L\xed\xf1p\xa3_\xcb\xde6\xa4\xa6"Ex\xbfq{\xc7q%'
]

xe = []
with open('google.cert', 'rb') as p:
	xe = [p.read()]

#
cert = ssl.DER_cert_to_PEM_cert(xe[0][11:])
cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
print(cert.digest('SHA1'), (cert.get_extension_count()), encrypt_string(xe[0][11:]), cert, cert.get_subject(), len(xe[0]))
exit()

x = 0
while True:
	#xe = [base64.b64decode(x.encode())]
	try:
		cert = ssl.DER_cert_to_PEM_cert(xe[0][x:])
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
		print(cert, x)
	except Exception as e:
		print('Err')
		pass

	x += 1
	time.sleep(1)
exit()
#print(xe[0])
#exit([len(xe[0])])
#cert = x[0]
#message_bytes = base64.b64decode(x)
#exit([message_bytes])  #, encrypt_string(message_bytes), cert.digest('SHA256')])

from OpenSSL import crypto
cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
#x = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert)
#print(x)
#exit(cert)
print(cert.digest('SHA256'), (cert.get_extension_count()), encrypt_string(xe[0]), cert, cert.get_subject(), len(xe[0]))

exit()


'''

#cert = x509.load_pem_x509_certificate(cert, default_backend())
#x = b'MIIFkzCCBHugAwIBAgIQUvtF6bzAHyEDAAAAAMMjOTANBgkqhkiG9w0BAQsFADBC\nMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMw\nEQYDVQQDEwpHVFMgQ0EgMU8xMB4XDTIwMTIxNTE0MzYxNVoXDTIxMDMwOTE0MzYx\nNFowaDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT\nDU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFzAVBgNVBAMTDnd3\ndy5nb29nbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqPmk\nrg4JZBqxukAqXcsIyoQ7EfkoYZooKy9OGOk0FsbA662QAhRvLyScRnAaKLeT/s1p\nlOzLIguQKCl8GkrNJRWjhhG9G95IWGOCuOxjdvRWF5RADpIPbapGAH0awFsO9hlg\nVzxsuZC+hHOrAVvUAI5x7tYhz6SYMjsbj0BUz2WzEnSXonY85Zy825rFBjpfJf69\nCGJpCx1+T4w7USP7GqsdpI8kNSHfFSbt7Z8U5mdn4LG7tvaMS/oVlcE2P5O09lDT\nYz1+MlxIeQnzSFt0R9S2Xrbv6oNuEdzoqKFXEHcQ+SDcf4Kb5ghpPezjiufwtotR\n/gwqXHrMLTZ3lzsMzQIDAQABo4ICXTCCAlkwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud\nJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGfXwgDfHBsH\noA7W51LPuYfBeHI0MB8GA1UdIwQYMBaAFJjR+G4Q68+b7GCfGJAboOt9Cf0rMGgG\nCCsGAQUFBwEBBFwwWjArBggrBgEFBQcwAYYfaHR0cDovL29jc3AucGtpLmdvb2cv\nZ3RzMW8xY29yZTArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RT\nMU8xLmNydDAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNvbTAhBgNVHSAEGjAYMAgG\nBmeBDAECAjAMBgorBgEEAdZ5AgUDMDMGA1UdHwQsMCowKKAmoCSGImh0dHA6Ly9j\ncmwucGtpLmdvb2cvR1RTMU8xY29yZS5jcmwwggEFBgorBgEEAdZ5AgQCBIH2BIHz\nAPEAdgD2XJQv0XcwIhRUGAgwlFaO400TGTO/3wwvIAvMTvFk4wAAAXZnC4CJAAAE\nAwBHMEUCIERZyIP0GBfWUDPpmMCMVYBgpSKpIQuqnsFo2MoRHDWsAiEA/+nQTy9E\nsKLKfzDABLRUz/P+TZGGjM7UVQjtWe/+s+sAdwBc3EOS/uarRUSxXprUVuYQN/vV\n+kfcoXOUsl7m9scOygAAAXZnC4C7AAAEAwBIMEYCIQCPyfB8H0em1gHv8QQeF4zN\nHkfv47lQjNsszABWeYXfwwIhAKngHPHb1UKDE3LMF6FYEdsGOK63kdIfUuyWLX0A\nUYszMA0GCSqGSIb3DQEBCwUAA4IBAQAbkVw9feVP0maVCLVO/TKFBQWgcQTHtJGI\nk2YTSZCSwLYe7Xboae5t6inwKu0yB+bYqUC2itFpv7BCsZv4rPOH6zBHHH2CSlZB\n1XI40WrnPwGMr3P1aR2dsUw1gDEXFwgXdFbL/u/9WUjeUogQULSFxqJXrYB693az\n96FCwtoSg3+WC5IcEJElDEE0kgS8o5ZyJ4GLmLBYsWcMkbx80/pDf71ylBts63e0\nu5k2sQuBcNhIGaRIFmP9SHYXyTtSlaB84RwThgkhr40S3QZWDNiqht2WnM65UHUR\nCVEiml3bIKMz+fLaOgroFKQy8uBw7tei+gzbbqqyJbicdgcSDgd3'
'''
#exit()
hostname = 'www.google.com'
port = 443
cert = ssl.get_server_certificate((hostname, port), ssl_version=ssl.PROTOCOL_TLSv1_2)
#exit(cert)
#exit([cert])
certDecoded = x509.load_pem_x509_certificate(str.encode(cert), default_backend())
exit([str.encode(cert)])
#cert = x509.load_pem_x509_certificate(cert, default_backend())
cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
print(cert.digest('SHA256'), cert, cert.get_subject())
#print(cert.subject)
##print(certDecoded.not_valid_after)
#print(certDecoded.not_valid_before)
exit()
'''
"""
def get_certificate(host, port=443, timeout=10):
	context = ssl.create_default_context()
	conn = socket.create_connection((host, port))
	sock = context.wrap_socket(conn, server_hostname=host)
	sock.settimeout(timeout)
	try:
		der_cert = sock.getpeercert(True)
	finally:
		sock.close()

	print(ssl.DER_cert_to_PEM_cert(der_cert))
	exit()
	return ssl.DER_cert_to_PEM_cert(der_cert)


certificate = get_certificate('www.google.com')
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

result = {
	'subject': dict(x509.get_subject().get_components()),
	'issuer': dict(x509.get_issuer().get_components()),
	'serialNumber': x509.get_serial_number(),
	'version': x509.get_version(),
	#'notBefore': datetime.strptime(x509.get_notBefore(), '%Y%m%d%H%M%SZ'),
	#'notAfter': datetime.strptime(x509.get_notAfter(), '%Y%m%d%H%M%SZ'),
}

extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
extension_data = {e.get_short_name(): str(e) for e in extensions}
result.update(extension_data)
pprint(result)

exit()
"""
'''
cert = ssl.get_server_certificate(('www.google.com', 443))  #, ssl_version=ssl.PROTOCOL_TLSv1_2)

from OpenSSL import crypto  # pip install pyopenssl
#with open('out.cert', 'r') as p:
#	cert = p.read()

cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
print(cert.digest('SHA256'), cert, cert.get_subject().CN)

'''

#exit()
buffer = io.BytesIO()
buffer2 = io.BytesIO()
buffer3 = io.BytesIO()
c = pycurl.Curl()

#help(c)

c.setopt(c.URL, "https://api.ipify.org/")
c.setopt(c.URL, "https://www.google.com/")
#c.setopt(c.VERBOSE, True)  # to see request details
c.setopt(pycurl.HEADERFUNCTION, buffer.write)
c.setopt(c.SSLVERSION, c.SSLVERSION_TLSv1_2)
#c.setopt(pycurl.SSLVERSION_MAX_DEFAULT, pycurl.SSLVERSION_TLSv1_2)
c.setopt(pycurl.WRITEFUNCTION, buffer2.write)

x = 0


def test(debug_type, debug_msg):
	global x
	if b'TLSv1.3 (IN), TLS handshake, Certificate (11)' in debug_msg:
		print("debug(%d): %s" % (debug_type, debug_msg))
		x = 1
		return

	if x == 11:

		cert = ssl.DER_cert_to_PEM_cert(debug_msg[0][11:])
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
		print(cert.digest('SHA1'), (cert.get_extension_count()), cert, cert.get_subject())
		exit()

		import binascii
		from cryptography import x509
		from cryptography.hazmat.backends import default_backend
		with open('google.cert', 'wb') as p:
			p.write(debug_msg)

		#exit([debug_msg])
		certificate = ssl.DER_cert_to_PEM_cert(b'\x08\x00\x00\x0b\x00\t\x00\x10\x00\x05\x00\x03\x02h2')
		print(certificate)
		exit()
		#x509.load_der_x509_certificate(debug_msg, default_backend())
		exit("kkkk")
		#certDecoded = x509.load_pem_x509_certificate(str.encode(certificate), default_backend())
		#OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, certificate)
		exit([certificate])
		cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
		exit([cert])
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
		print([x509])
		exit()
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, ssl.DER_cert_to_PEM_cert(debug_msg))
		print(cert.digest('SHA256'), cert, cert.get_subject().CN)

		#print(debug_msg.decode('iso-8859-1'))
		exit()

	print("debug(%d): %s" % (debug_type, debug_msg))


#c.setopt(pycurl.DEBUGFUNCTION, test)
c.setopt(pycurl.OPT_CERTINFO, 1)
ts = time.perf_counter()
c.perform()
certinfo = c.getinfo(c.INFO_CERTINFO)
print([certinfo])
exit()
resp = buffer.getvalue()

m = {}
m['total-time'] = c.getinfo(pycurl.TOTAL_TIME)
m['namelookup-time'] = c.getinfo(pycurl.NAMELOOKUP_TIME)
m['connect-time'] = c.getinfo(pycurl.CONNECT_TIME)
m['pretransfer-time'] = c.getinfo(pycurl.PRETRANSFER_TIME)
m['redirect-time'] = c.getinfo(pycurl.REDIRECT_TIME)
m['starttransfer-time'] = c.getinfo(pycurl.STARTTRANSFER_TIME)

#print(m, resp, "=====", buffer2.getbuffer().tobytes(), "=====", buffer3.getbuffer().tobytes())
#print(tme.perf_counter() - ts)
