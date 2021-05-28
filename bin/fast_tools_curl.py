import time, re, ipaddress, io, pycurl
from urllib.parse import scheme_chars, urlencode, urljoin, urlparse, parse_qs, urlunparse, ParseResult, quote
from easy_timezones.utils import is_valid_ip
import http.server
from base64 import b64encode
from datetime import datetime
from OpenSSL import crypto
import base64, binascii, hashlib
from cryptography.hazmat.primitives import serialization


def Robotcookie(cookie: str, parent_domain: str):
	items = cookie.split(';')
	SameSite = HttpOnly = Secure = Domain = Path = Expires = Comment = MaxAge = CookieName = CookieValue = Size = Sessionkey = Version = Priority = None
	CookieName = CookieValue = None
	idx = len(items) - 1
	while idx >= 0:
		item = items[idx].strip()
		idx -= 1
		if not item:
			continue

		SameSiteMatched = re.match(r'^SameSite(.*)?', item, re.I)
		HttpOnlyMatched = SameSiteMatched or re.match(r'^HttpOnly(.*)$', item, re.I)
		SecureMatched = HttpOnlyMatched or re.match(r'^Secure(.*)$', item, re.I)
		DomainMatched = SecureMatched or re.match(r'^Domain(.*)?', item, re.I)
		PathMatched = DomainMatched or re.match(r'^Path(.*)?', item, re.I)
		ExpiresMatched = PathMatched or re.match(r'^Expires(.*)?', item, re.I)
		CommentMatched = ExpiresMatched or re.match(r'^Comment(.*)?', item, re.I)
		MaxAgeMatched = ExpiresMatched or re.match(r'^Max-Age=(.*)?', item, re.I)
		VersionMatched = MaxAgeMatched or re.match(r'^Version=(.*)?', item, re.I)
		PriorityMatched = VersionMatched or re.match(r'^priority=(.*)?', item, re.I)
		#print(PriorityMatched)
		matched = SameSiteMatched or HttpOnlyMatched or SecureMatched or DomainMatched or PathMatched or ExpiresMatched or CommentMatched or MaxAgeMatched or VersionMatched or PriorityMatched
		if matched:
			val = matched.groups(0)[0].lstrip('=')
			if matched == SameSiteMatched:
				SameSite = val if val.lower() in ['strict', 'lax', 'none'] else None
			elif matched == HttpOnlyMatched:
				HttpOnly = True
			elif matched == SecureMatched:
				Secure = True
			elif matched == DomainMatched:
				Domain = val
			elif matched == PathMatched:
				Path = val
			elif matched == PathMatched:
				Path = val
			elif matched == ExpiresMatched:
				Expires = val
			elif matched == CommentMatched:
				Comment = val
			elif matched == MaxAgeMatched:
				MaxAge = val
			elif matched == VersionMatched:
				Version = val
			elif matched == PriorityMatched:
				Priority = val
		else:
			CookieMatched = re.match(r'^(.[^=]*)=(.*)?', item, re.I)
			if CookieMatched:
				CookieName, CookieValue = CookieMatched.groups(0)

	Sessionkey = True if not Expires else False
	Size = (len(CookieName) if CookieName else 0) + (len(CookieValue) if CookieValue else 0)

	Domain = parent_domain if not Domain else Domain
	Path = '/' if not Path else Path
	Priority = 'Medium' if CookieName and not Priority else Priority.title() if Priority else 'Medium'
	Expires_Days = None
	if Expires:
		try:
			date = datetime.strptime(Expires, "%a, %d-%b-%Y %H:%M:%S %Z")
			Expires_Days = int((date - datetime.now()).total_seconds())
		except Exception as e:
			pass
	elif MaxAge:
		Expires_Days = MaxAge

	#exit([Expires_Days])
	Cookie = {
	    CookieName: CookieValue,
	    'Domain': Domain,
	    'Path': Path,
	    'Expires': Expires,
	    'Expires_Days': Expires_Days,
	    'Comment': Comment,
	    'MaxAge': MaxAge,
	    'SameSite': SameSite,
	    'HttpOnly': HttpOnly,
	    'Secure': Secure,
	    'Size': Size,
	    'Sessionkey': Sessionkey,
	    'Version': Version,
	    'Priority': Priority
	}
	return Cookie if CookieName else None
	#exit([idx, CookieName, CookieValue, SameSite, HttpOnly, Secure, Domain, Path, Expires, Comment, MaxAge, Cookie])


class ERROR_CODES:
	OK = (0x0, '+OK')
	UNKNONWN = (0x1, 'Unknown error.')
	MALFORM_URL = (0x2, 'Malform error.')
	WRONG_HTTP_VERSION = (0x3, 'Invalid HTTP version.')
	INVALID_RESOLVE_IP = (0x4, 'Invalid Resolve IP.')

	@classmethod
	def new(self, Err_No: int, Err_Msg: str):
		return (Err_No if Err_No is not None else 1, Err_Msg)


class HTTP_VERSION:
	V1_0 = 0x1
	V1_1 = 0x2
	V2_0 = 0x3


class HTTP_METHOD:
	GET = 'GET'
	POST = 'POST'


class Curl:
	@classmethod
	def cb_debug(self, response: dict, debug_Type: int, buffer: str, request_headers, request_sent_time_ms: dict):
		if debug_Type == 0 and response['ssl_version'] is None:
			ssl_v = re.match(r'SSL connection using (.[^/]*) / (.*)', buffer.decode())
			if ssl_v:
				response['ssl_version'], response['ssl_cipher_suite'] = ssl_v.groups(0)
			#exit([ssl_version])
		if debug_Type == 0 and response['remote_address'] is None:
			ip4 = re.findall(r'Trying (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})', buffer.decode(), re.I | re.M)
			if ip4:
				response['remote_address'] = ip4[0]

		if debug_Type == 2:
			request_headers.write(buffer)
			if request_sent_time_ms['start'] is None:
				request_sent_time_ms['start'] = time.perf_counter() * 1000
				#exit([request_sending_start_time_ms])

		if request_sent_time_ms['start'] is not None and request_sent_time_ms['end'] is None:
			request_sent_time_ms['end'] = time.perf_counter() * 1000

		#print(debug_Type, buffer)
		#time.sleep(2)

	@classmethod
	def default_headers(self, user_agent: str = None):
		httpheaders = [
		    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8', 'Accept-Encoding: gzip, deflate',
		    'Cache-Control: max-age=0', 'Upgrade-Insecure-Requests: 1'
		]
		return httpheaders + ([user_agent] if user_agent else [])

	@classmethod
	def build_uri_scheme(self, uri: str):
		if uri.lower().startswith('//'):
			uri = 'http://{}'.format(uri.strip("//"))
		elif not uri.lower().startswith('http://') and not uri.lower().startswith('https://'):
			Uri = f'http://{uri}'
		return uri

	@classmethod
	def default_response(self, uri: str, method=HTTP_METHOD.GET):
		response = {}
		response['errno'], response['errmsg'] = ERROR_CODES.UNKNONWN
		response['url'] = uri
		response['method'] = method
		response['version'] = None
		response['status'] = (-1, '-OK')
		response['address'] = None,
		response['compressed'] = None,
		response['transfered'] = (0, 0)
		response['referer_policy'] = None
		response['ssl_version'] = None
		response['ssl_secure'] = None
		response['content_type'] = None
		response['scheme'] = None
		response['domain'] = None
		response['port'] = None
		response['username'] = None
		response['password'] = None
		response['path'] = None
		response['query'] = None
		response['fragment'] = None

		response['get_params_decoded'] = None
		response['get_params_encoded'] = None
		response['get_params_raw'] = None
		response['get_params_szie'] = None

		response['post_params_decoded'] = None
		response['post_params_encoded'] = None
		response['post_params_raw'] = None
		response['post_params_szie'] = None

		response['request_cookies'] = None
		response['request_cookies_raw'] = None
		response['request_cookies_size'] = None

		response['response_cookies'] = None
		response['response_cookies_raw'] = None
		response['response_cookies_size'] = None

		response['request_headers_map'] = None
		response['request_headers_raw'] = None
		response['request_headers_size'] = None
		response['response_headers_map'] = None
		response['response_headers_raw'] = None
		response['response_headers_size'] = None

		response['ssl_version'] = None
		response['ssl_cipher_suite'] = None
		response['ssl_key_exchange_group'] = None
		response['ssl_cert_signature_algorithm'] = None
		response['ssl_domain'] = None
		response['strict_transport_security'] = None
		#response['public_key_pinning'] = None
		response['ssl_public_key_pinning'] = None
		response['ssl_cert_issued_to_cn'] = None
		response['ssl_cert_issued_to_o'] = None
		response['ssl_cert_issued_to_ou'] = None
		response['ssl_cert_issued_to_l'] = None
		response['ssl_cert_issued_to_st'] = None
		response['ssl_cert_issued_to_c'] = None
		response['ssl_cert_issued_by_cn'] = None
		response['ssl_cert_issued_by_o'] = None
		response['ssl_cert_issued_by_ou'] = None
		response['ssl_cert_issued_by_u'] = None
		response['ssl_cert_issued_by_l'] = None
		response['ssl_cert_issued_by_st'] = None
		response['ssl_cert_issued_by_c'] = None
		response['ssl_cert_validity_begins_on'] = None
		response['ssl_cert_validity_expires_on'] = None
		response['ssl_fingerprints_sha256'] = None
		response['ssl_fingerprints_sha1'] = None
		response['ssl_fingerprints_md5'] = None

		response['blocked_time_ms'] = None
		response['dns_resolution_time_ms'] = None
		response['connecting_time_ms'] = None
		response['ssl_setup_time_ms'] = None
		response['pretransfer_time_ms'] = None
		response['sending_time_ms'] = None
		response['redirct_time_ms'] = None
		response['waiting_time_ms'] = None
		response['receive_time_ms'] = None
		response['total_time_ms'] = None

		return response

	@classmethod
	def _parse_url(self, uri: str, response: dict):
		try:
			response['url'] = uri
			uparts = urlparse(uri)
			response['scheme'] = uparts.scheme if uparts.scheme else None
			response['host'] = uparts.hostname if uparts.hostname else None
			response['port'] = int(uparts.port) if uparts.port else None
			response['username'] = uparts.username if uparts.username else None
			response['password'] = uparts.password if uparts.password else None

			response['params'] = parse_qs(uparts.query) if uparts.query else None
			response['fragment'] = uparts.fragment if uparts.fragment else None

			query = self.build_get_params(uparts.query, response)

			#exit(query)
			response['query'] = query
			response['path'] = uparts.path if uparts.path else '/'
			#exit([uparts.path])
			response['request_uri'] = "{}{}{}".format(response['path'] if response['path'] else '/', '?' if query else '', query if query else '')
			#exit(response['request_uri'])
			#+ '{qrystr}'.format(qrystr=('?' + uparts.query) if uparts.query else '/' + "") + ('#{fragment}'.format(fragment=uparts.fragment) if uparts.fragment else '')
			netloc = '{domain}{port}'.format(domain=response['host'], port=':{}'.format(response['port']) if response['port'] else '')
			Uri = ParseResult(scheme=response['scheme'], netloc=netloc, path=response['path'] if response['path'] else '', params=[], query=query, fragment=response['fragment']).geturl()
			#exit(Uri)
			response['url'] = Uri
			response['domain'] = response['host']
			response['port'] = response['port'] if response['port'] else 443 if response['scheme'].lower() == 'https' else 80
			response['errno'], response['errmsg'] = ERROR_CODES.OK
			#exit([response])
		except Exception as e:
			raise e
			response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_URL

		post_data = {}
		self.build_post_params(post_data, response)

	@classmethod
	def _validate_resolve(self, resolve, response):
		resolve_hosts = []
		if not resolve:
			return (False, None)

		if not isinstance(resolve, str) or not is_valid_ip(resolve) or not isinstance(ipaddress.ip_address(resolve), ipaddress.IPv4Address):
			response['errno'], response['errmsg'] = ERROR_CODES.INVALID_RESOLVE_IP
			return (True, None)
		#
		resolve_hosts = ['{}:{}:{}'.format(response['host'], response['port'] if response['port'] else 80 if response['scheme'] else 443, resolve)]
		response['address'] = resolve
		return (False, resolve_hosts)

	@classmethod
	def _exec_get(self, uri: str, http_version, httpheaders, user_agent: str, insecure: bool, resolve_hosts: str, hfun_buffer: io.BytesIO, request_headers: io.BytesIO, http_buffer: io.BytesIO, request_sent_time_ms: dict, response: dict):

		response['remote_address'] = None

		c = pycurl.Curl()
		c.setopt(pycurl.URL, uri)
		c.setopt(pycurl.VERBOSE, True)  # to see request details
		c.setopt(pycurl.HEADERFUNCTION, hfun_buffer.write)
		c.setopt(pycurl.DEBUGFUNCTION, lambda d, b: self.cb_debug(response, d, b, request_headers, request_sent_time_ms))
		c.setopt(pycurl.ACCEPT_ENCODING, 'gzip, deflate')
		c.setopt(pycurl.WRITEDATA, http_buffer)
		c.setopt(pycurl.USERAGENT, user_agent)
		c.setopt(pycurl.OPT_CERTINFO, 1)
		c.setopt(pycurl.DNS_CACHE_TIMEOUT, 1)
		#c.setopt(pycurl.DNS_SERVERS, None)
		c.setopt(pycurl.FOLLOWLOCATION, False)
		c.setopt(pycurl.FAILONERROR, True)

		c.setopt(pycurl.HEADER, True)
		#c.setopt(pycurl.IGNORE_CONTENT_LENGTH, True)
		c.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
		c.setopt(pycurl.CONNECTTIMEOUT, 5)
		c.setopt(pycurl.TCP_FASTOPEN, True)
		c.setopt(pycurl.TIMEOUT, 10)
		if resolve_hosts:
			c.setopt(pycurl.RESOLVE, [resolve_hosts])
		c.setopt(pycurl.HTTP_VERSION, http_version)
		c.setopt(pycurl.NOSIGNAL, 1)
		c.setopt(pycurl.NOPROGRESS, 1)
		c.setopt(pycurl.HTTPHEADER, httpheaders)

		if insecure:
			c.setopt(pycurl.SSL_VERIFYHOST, False)
			c.setopt(pycurl.SSL_VERIFYPEER, False)

		err = True
		curl_info = {}
		try:
			c.perform()
			err = False
		except pycurl.error as exc:
			if exc.args[0] == pycurl.E_HTTP_RETURNED_ERROR:
				err = False
			else:
				response['errno'], response['errmsg'] = tuple(exc.args)
		except Exception as exc:
			response['errno'], response['errmsg'] = ERROR_CODES.new(None, tuple(exc.args)[0])

		remote_address = response['remote_address']
		del response['remote_address']
		#exit([remote_address, 22])
		if err:
			hfun_buffer.close()
			request_headers.close()
			http_buffer.close()
		else:

			#exit([c.getinfo(pycurl.SIZE_DOWNLOAD)])
			curl_info[pycurl.SIZE_DOWNLOAD] = c.getinfo(pycurl.SIZE_DOWNLOAD)
			pycurl.SIZE_DOWNLOAD
			curl_info[pycurl.PRIMARY_IP] = c.getinfo(pycurl.PRIMARY_IP)
			curl_info[pycurl.PRIMARY_PORT] = c.getinfo(pycurl.PRIMARY_PORT)
			if not curl_info[pycurl.PRIMARY_IP] and remote_address:
				curl_info[pycurl.PRIMARY_IP] = remote_address[0]
				response['address'] = remote_address[0]
			if not curl_info[pycurl.PRIMARY_PORT] and remote_address:
				curl_info[pycurl.PRIMARY_PORT] = remote_address[1]
				response['port'] = remote_address[1]
			#exit([response['address'], response['port']])
			curl_info[pycurl.INFO_CERTINFO] = c.getinfo(pycurl.INFO_CERTINFO)
			curl_info[pycurl.EFFECTIVE_URL] = c.getinfo(pycurl.EFFECTIVE_URL)
			curl_info[pycurl.INFO_HTTP_VERSION] = c.getinfo(pycurl.INFO_HTTP_VERSION)
			curl_info[pycurl.HTTP_CODE] = c.getinfo(pycurl.HTTP_CODE)
			curl_info[pycurl.NAMELOOKUP_TIME] = c.getinfo(pycurl.NAMELOOKUP_TIME)
			curl_info[pycurl.CONNECT_TIME] = c.getinfo(pycurl.CONNECT_TIME)
			curl_info[pycurl.APPCONNECT_TIME] = c.getinfo(pycurl.APPCONNECT_TIME)
			curl_info[pycurl.PRETRANSFER_TIME] = c.getinfo(pycurl.PRETRANSFER_TIME)
			curl_info[pycurl.STARTTRANSFER_TIME] = c.getinfo(pycurl.STARTTRANSFER_TIME)
			curl_info[pycurl.REDIRECT_TIME] = c.getinfo(pycurl.REDIRECT_TIME)
			curl_info[pycurl.TOTAL_TIME] = c.getinfo(pycurl.TOTAL_TIME)
			c.close()
		return (err, curl_info)

	@classmethod
	def _status_code(self, http_code):
		status_code = http_code
		status_msg = 'No Reason'
		if http_code in http.server.BaseHTTPRequestHandler.responses:
			status_msg = http.server.BaseHTTPRequestHandler.responses[http_code][0]
		return (status_code, status_msg)

	@classmethod
	def calculate_timmings(self, curl_info: dict, response: dict, request_sent_time_ms: dict):

		blocked_time_ms = 0
		dns_resolution_time_ms = 0
		connecting_time_ms = 0
		ssl_setup_time_ms = 0
		pretransfer_time_ms = 0
		sending_time_ms = 0
		redirct_time_ms = 0
		waiting_time_ms = 0
		receive_time_ms = 0

		NAMELOOKUP_TIME = curl_info[pycurl.NAMELOOKUP_TIME] * 1000
		CONNECT_TIME = curl_info[pycurl.CONNECT_TIME] * 1000
		APPCONNECT_TIME = curl_info[pycurl.APPCONNECT_TIME] * 1000
		PRETRANSFER_TIME = curl_info[pycurl.PRETRANSFER_TIME] * 1000
		STARTTRANSFER_TIME = curl_info[pycurl.STARTTRANSFER_TIME] * 1000
		REDIRECT_TIME = curl_info[pycurl.REDIRECT_TIME] * 1000
		TOTAL_TIME = curl_info[pycurl.TOTAL_TIME] * 1000

		#exit([TOTAL_TIME])
		dns_resolution_time_ms = NAMELOOKUP_TIME
		connecting_time_ms = CONNECT_TIME - NAMELOOKUP_TIME
		ssl_setup_time_ms = APPCONNECT_TIME - CONNECT_TIME
		pretransfer_time_ms = PRETRANSFER_TIME - APPCONNECT_TIME
		redirct_time_ms = REDIRECT_TIME

		#exit([request_sent_time_ms, 111])
		if request_sent_time_ms['start'] and request_sent_time_ms['end']:
			sending_time_ms = request_sent_time_ms['end'] - request_sent_time_ms['start']
		waiting_time_ms = STARTTRANSFER_TIME - PRETRANSFER_TIME - sending_time_ms
		receive_time_ms = TOTAL_TIME - STARTTRANSFER_TIME
		totaltime_ms = sum([dns_resolution_time_ms, connecting_time_ms, ssl_setup_time_ms, pretransfer_time_ms, sending_time_ms, waiting_time_ms, receive_time_ms])

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
		response['redirct_time_ms'] = redirct_time_ms
		response['waiting_time_ms'] = waiting_time_ms
		response['receive_time_ms'] = receive_time_ms
		response['total_time_ms'] = totaltime_ms

	@classmethod
	def _basic_auth(self, httpheaders, response):
		if response['username'] and response['password']:
			userAndPass = b64encode("{}:{}".format(response['username'], response['password']).encode()).decode("ascii")
			httpheaders.append('Authorization: ' + 'Basic %s' % userAndPass)

	@classmethod
	def _parse_response_headers(self, hfun_buffer: io.BytesIO, parent_domain: str, response: dict):
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
		response_cookies_raw = []
		#exit([res_headers])

		cookies_size = 0
		for header in res_headers:
			if not header:
				continue

			if not resp_msg and header.startswith('HTTP/'):
				resp_msg = header
				continue

			parts = header.split(':', 1)
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
				response_cookies_raw.append(val)
				#exit([response_cookies_raw])
				_cookie = Robotcookie(val, parent_domain)
				cookies_size += _cookie['Size']
				Cookies.append(_cookie)

		headers_str.insert(0, resp_msg)

		response['response_headers_map'] = headers_dict
		response['response_headers_raw'] = "\r\n".join(headers_str)
		response['response_headers_size'] = len(response['response_headers_raw'])

		#exit([response['resposne_headers_map']])
		#exit([response['resposne_headers_raw']])
		#response['request_headers_size'] = len(response['request_headers_raw'])
		#response['request_headers_map'] = headers_dict
		#response['request_cookies'] = Cookies

		response['content_type'] = Content_Type
		response['strict_transport_security'] = Strict_Transport_Security
		response['content_encoding'] = Content_Encoding
		response['compressed'] = any([Content_Encoding and Content_Encoding == cp for cp in ['gzip', 'compress', 'br']])
		#response['response_headers_raw'] = "\r\n".join(headers_str)
		#response['response_headers_map'] = headers_dict
		#exit([response['compressed'], Content_Encoding])

		#exit([response_cookies_raw])
		response['response_cookies'] = Cookies
		response['response_cookies_raw'] = "\n".join(response_cookies_raw)
		response['response_cookies_size'] = cookies_size
		response['public_key_pins'] = Public_Key_Pins

		#set-cookie: NID=207=AA-ov3QLhcoZsyCbF0n9dB1U0JN5KdG9ArNc4-7hZNWxH6lgWIlfpz5sq39Mn-NS5z4wxWNkXYbepF-Wu1YFTyp2VvcNf4k1TooEzDfWWaWWWuz-WSB8aj9ZAsVdLJ5--6sJRnvuai5z7zi0Favm-oJoQc1BdyMcdtiGe_33Vj4; expires=Sun, 25-Jul-2021 15:49:05 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=none
		#exit([Content_Type, Strict_Transport_Security, Content_Encoding, headers_dict, headers_str, Cookies, Public_Key_Pins, headers_str])
		#exit([headers])

	@classmethod
	def _parse_request_headers(self, method: HTTP_METHOD.GET, request_headers: io.BytesIO, response: dict, httpheaders: list, parent_domain: str):
		headers = request_headers.getvalue().decode()
		#exit(headers)
		if (not headers):
			_headers = ["{} {} {}".format(method, response['request_uri'], response['version'])]
			_headers += httpheaders
			headers = "\r\n".join(_headers)

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
		#exit([response])

	@classmethod
	def analysis_security(self, curl_info: dict, response: dict):
		certinfo = curl_info[pycurl.INFO_CERTINFO]

		hostname = response['domain']

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
						Certificate_Secure = subject.CN and (subject.CN == hostname or (subject.CN.startswith('*.') and hostname.endswith(subject.CN[2:])))
						#exit([Certificate_Secure, hostname, subject.CN, subject.CN[2], hostname.endswith(subject.CN[2])])
						issuer = cert.get_issuer()

						Certificate_Issue_By_CN = issuer.CN
						Certificate_Issue_By_O = issuer.O
						Certificate_Issue_By_OU = issuer.OU

						Certificate_Issue_By_C = issuer.C
						Certificate_Issue_By_ST = issuer.ST
						Certificate_Issue_By_L = issuer.L

						pin_sha256 = None
						try:
							import binascii, hashlib
							pcert = ((cert.get_pubkey().to_cryptography_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)))
							pin_sha256 = base64.b64encode((hashlib.sha256(base64.b64decode(''.join(pcert.decode().split("\n")[1:-2]))).digest())).decode()
							#exit([pin_sha256])
						except Exception as e:
							pass
						#exit([pin_sha256])
						Certificate_Public_Key = None  #help(cert.get_pubkey())
						Certificate_Serial_No = cert.get_serial_number()
						#Certificate_Signature_Algorithm = cert.get_signature_algorithm()
						Certificate_Expired = cert.has_expired()
						#elp(Certificate_Signature_Algorithm)
						#exit([Certificate_Public_Key, Certificate_Serial_No, Certificate_Signature_Algorithm, Certificate_Expired])

						Fingerprints_sha256 = cert.digest('sha256').decode()
						#exit([Fingerprints_sha256, 333])
						Fingerprints_sha1 = cert.digest('sha1').decode()
						Fingerprints_md5 = cert.digest('md5').decode()
						bsha256 = base64.b64encode(binascii.a2b_hex(Fingerprints_sha256.replace(':', '')))
						Public_Key_Pinning_bs64 = pin_sha256  # bsha256.decode()
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
		#exit([response['ssl_secure']])
		response['ssl_key_exchange_group'] = Key_Exchange_Group

		response['ssl_fingerprints_sha256'] = Fingerprints_sha256
		response['ssl_fingerprints_sha1'] = Fingerprints_sha1
		response['ssl_fingerprints_md5'] = Fingerprints_md5

		response['ssl_public_key_pinning_bs64'] = Public_Key_Pinning_bs64
		response['ssl_domain'] = response['domain']

		response['ssl_public_key_pinning'] = None
		if response['ssl_public_key_pinning_bs64'] and response['public_key_pins'] and response['public_key_pins'].find(response['ssl_public_key_pinning_bs64']) >= 0:
			response['ssl_public_key_pinning'] = True

		#exit(response)
		#exit([c.getinfo(c.SSL_ENGINES)])
		#exit("analysis_security")

	@classmethod
	def update_response(self, curl_info, hfun_buffer: io.BytesIO, request_headers: io.BytesIO, response, httpheaders, request_sent_time_ms):
		response['status'] = self._status_code(curl_info[pycurl.HTTP_CODE])
		version = curl_info[pycurl.INFO_HTTP_VERSION]
		response['version'] = 'HTTP/1.1' if version == HTTP_VERSION.V1_1 else 'HTTP/1.0' if version == HTTP_VERSION.V1_0 else 'HTTP/2'

		try:
			response['domain'] = urlparse(curl_info[pycurl.EFFECTIVE_URL]).hostname
		except Exception as e:
			pass

		self._parse_response_headers(hfun_buffer, response['domain'], response)
		self._parse_request_headers(method=HTTP_METHOD.GET, request_headers=request_headers, response=response, httpheaders=httpheaders, parent_domain=response['domain'])
		self.calculate_timmings(curl_info, response, request_sent_time_ms)
		self.analysis_security(curl_info, response)

		response['request_cookies'] = []
		response['request_cookies_raw'] = ''
		response['request_cookies_size'] = 0

		response['referer_policy'] = 'no-referrer-when-downgrade'

		if curl_info[pycurl.HTTP_CODE] in [301, 302, 307] and response['response_headers_map']:
			currurl = curl_info[pycurl.EFFECTIVE_URL]
			for header in response['response_headers_map']:
				if header[0].lower() == 'location':
					response['redirect'] = urljoin(currurl, header[1])

			#exit([response['redirect']])

	@classmethod
	def build_get_params(self, query, response):
		#qyery = response['query']
		#query = 'hello[] =h llo w&search[]=hotel%20in+delhi&search[]=hotel%20in+agra&sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwiZq9_Km9LuAhVvwjgGHfySAmoQFjAJegQIBhAC&url=https%3A%2F%2Flaravel.com%2Fdocs%2F8.x%2Fhttp-tests&usg=AOvVaw3mJi0-VJdJ6U_ndurAmNmr'
		params = {}
		try:
			params = parse_qs(query, keep_blank_values=True) if query else {}
		except Exception as e:
			pass

		#
		get_params_decoded = [[param, val] for param, vals in params.items() for val in vals]
		get_params_encoded = [[param, quote(val, '')] for param, vals in params.items() for val in vals]
		get_params_raw = (urlencode([(pv[0], pv[1]) for pv in get_params_decoded]))
		get_params_size = len(get_params_raw)
		#exit([get_params_decoded, get_params_encoded, get_params_raw, get_params_size])
		response['get_params_decoded'] = get_params_decoded
		response['get_params_encoded'] = get_params_encoded
		response['get_params_raw'] = get_params_raw
		response['get_params_size'] = get_params_size

		return get_params_raw if get_params_raw else query

	@classmethod
	def build_post_params(self, post_str, response):
		response['post_params_decoded'] = []
		response['post_params_encoded'] = []
		response['post_params_raw'] = ''
		response['post_params_szie'] = 0

	@classmethod
	def Exec_Get(self, uri: str, user_agent: str, http_version=HTTP_VERSION.V1_1, insecure=False, resolve=None):
		httpheaders = self.default_headers(user_agent)
		uri = self.build_uri_scheme(uri)
		#exit([HttpHeaders, uri])
		response = self.default_response(uri)
		self._parse_url(uri, response)
		if response['errno']:
			return response

		if http_version not in [HTTP_VERSION.V1_0, HTTP_VERSION.V1_1, HTTP_VERSION.V2_0]:
			response['errno'], response['errmsg'] = ERROR_CODES.WRONG_HTTP_VERSION
			return response

		self._parse_url(uri, response)
		response['version'] = 'HTTP/1.1' if http_version == HTTP_VERSION.V1_1 else 'HTTP/1.0' if http_version == HTTP_VERSION.V1_0 else 'HTTP/2'
		err, resolve_hosts = self._validate_resolve(resolve, response)
		#exit([err, resolve_hosts])
		if err:
			return response

		self._basic_auth(httpheaders, response)
		request_headers, hfun_buffer, http_buffer = io.BytesIO(), io.BytesIO(), io.BytesIO()
		request_sent_time_ms = {'start': None, 'end': None}
		err, curl_info = self._exec_get(uri, http_version, httpheaders, user_agent, insecure, resolve_hosts, hfun_buffer, request_headers, http_buffer, request_sent_time_ms, response)
		#exit([err, curl_info])
		if err:
			return response

		self.update_response(curl_info, hfun_buffer, request_headers, response, httpheaders, request_sent_time_ms)
		response['transferred'] = http_buffer.__sizeof__()
		response['transferred'] += hfun_buffer.__sizeof__()
		response['transferred'] = pycurl.SIZE_DOWNLOAD
		response['transfered'] = [curl_info[pycurl.SIZE_DOWNLOAD], curl_info[pycurl.SIZE_DOWNLOAD]]
		response['referrer_policy'] = 'no-referrer-when-downgrade'
		return response
		exit()
		#exit(response['status'])
		#exit([response['version']])
		self.calculate_timmings(curl_info, response, request_sent_time_ms)
		#exit(response)
		self.analysis_security(curl_info, response, response['host'])
		'''
		c.getinfo(c.HTTP_CODE)
		response['status'] = 'No Reason'
		
		#exit([request_headers])
		version = c.getinfo(pycurl.INFO_HTTP_VERSION)
		
		

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

		_parse_request_headers(HTTP_METHOD_GET, request_headers, response, httpheaders, cookie_host)
		_parse_response_headers(hfun_buffer, cookie_host, response)
		
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
		'''