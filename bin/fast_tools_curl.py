import time, re, ipaddress, io, pycurl
from urllib.parse import scheme_chars, urlparse, parse_qs, urlunparse, ParseResult
from easy_timezones.utils import is_valid_ip
import http.server


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
		if debug_Type == 2:
			request_headers.write(buffer)
			if request_sent_time_ms['start'] is None:
				request_sent_time_ms['start'] = time.perf_counter() * 1000
				#exit([request_sending_start_time_ms])

		if request_sent_time_ms['start'] is not None and request_sent_time_ms['end'] is None:
			request_sent_time_ms['end'] = time.perf_counter() * 1000

		#print(debug_Type, time.time(), Buffer)

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
		response['status'] = (-1, '-OK'),
		response['address'] = None,
		response['compressed'] = None,
		response['transfered'] = (None, None),
		response['referer_policy'] = None,
		response['ssl_version'] = None,
		response['ssl_secure'] = None,
		response['content_type'] = None,
		response['scheme'] = None
		response['domain'] = None,
		response['port'] = None,
		response['user'] = None,
		response['password'] = None,
		response['path'] = None,
		response['query'] = None,
		response['fragment'] = None,

		response['get_params'] = None,
		response['get_params_encoded'] = None,
		response['get_params_raw'] = None,
		response['get_params_szie'] = None,

		response['post_params'] = None,
		response['post_params_encoded'] = None,
		response['post_params_raw'] = None,
		response['post_params_szie'] = None,

		response['request_cookies'] = None,
		response['request_cookies_raw'] = None,
		response['request_cookies_size'] = None,

		response['response_cookies'] = None,
		response['response_cookies_raw'] = None,
		response['response_cookies_size'] = None,

		response['request_headers_map'] = None,
		response['request_headers_raw'] = None,
		response['request_headers_size'] = None,
		response['response_headers_map'] = None,
		response['response_headers_raw'] = None,
		response['response_headers_size'] = None,

		response['ssl_version'] = None,
		response['ssl_cipher_suite'] = None,
		response['ssl_key_exchange_group'] = None,
		response['ssl_cert_signature_algorithm'] = None,
		response['ssl_domain'] = None,
		response['strict_transport_security'] = None,
		response['public_key_pinning'] = None,
		response['public_key_pins'] = None,
		response['ssl_cert_issued_to_cn'] = None,
		response['ssl_cert_issued_to_o'] = None,
		response['ssl_cert_issued_to_ou'] = None,
		response['ssl_cert_issued_to_l'] = None,
		response['ssl_cert_issued_to_st'] = None,
		response['ssl_cert_issued_to_c'] = None,
		response['ssl_cert_issued_by_cn'] = None,
		response['ssl_cert_issued_by_o'] = None,
		response['ssl_cert_issued_by_ou'] = None,
		response['ssl_cert_issued_by_u'] = None,
		response['ssl_cert_issued_by_l'] = None,
		response['ssl_cert_issued_by_st'] = None,
		response['ssl_cert_issued_by_c'] = None,
		response['ssl_cert_validity_begins_on'] = None,
		response['ssl_cert_validity_expires_on'] = None,
		response['ssl_fingerprints_sha256'] = None,
		response['ssl_fingerprints_sha1'] = None,
		response['ssl_fingerprints_md5'] = None,

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
			response['query'] = uparts.query if uparts.query else None
			response['params'] = parse_qs(uparts.query) if uparts.query else None
			response['fragment'] = uparts.fragment if uparts.fragment else None
			response['filename'] = uparts.path if uparts.path else None
			response['request_uri'] = (uparts.path + '?{qrystr}'.format(qrystr=uparts.query) if uparts.query else '/') + "" + ('#{fragment}'.format(fragment=uparts.fragment) if uparts.fragment else '')
			netloc = '{domain}{port}'.format(domain=response['host'], port=':{}'.format(response['port']) if response['port'] else '')
			Uri = ParseResult(scheme=response['scheme'], netloc=netloc, path=response['filename'] if response['filename'] else '', params={}, query=response['query'], fragment=response['fragment']).geturl()
			response['url'] = Uri
			response['domain'] = response['host']
			response['port'] = response['port'] if response['port'] else 443 if response['scheme'].lower() == 'https' else 80
			response['errno'], response['errmsg'] = ERROR_CODES.OK
			exit(response)
		except Exception as e:
			raise e
			response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_URL

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
		c.setopt(pycurl.IGNORE_CONTENT_LENGTH, True)
		c.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
		c.setopt(pycurl.CONNECTTIMEOUT, 5)
		c.setopt(pycurl.TCP_FASTOPEN, True)
		c.setopt(pycurl.TIMEOUT, 10)
		c.setopt(c.RESOLVE, resolve_hosts)
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

		#exit([err, 22])
		if err:
			hfun_buffer.close()
			request_headers.close()
			http_buffer.close()
		else:
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

		request_headers, hfun_buffer, http_buffer = io.BytesIO(), io.BytesIO(), io.BytesIO()
		request_sent_time_ms = {'start': None, 'end': None}
		err, curl_info = self._exec_get(uri, http_version, httpheaders, user_agent, insecure, resolve_hosts, hfun_buffer, request_headers, http_buffer, request_sent_time_ms, response)
		#exit([err, curl_info])
		if err:
			return response

		response['status'] = self._status_code(curl_info[pycurl.HTTP_CODE])
		version = curl_info[pycurl.INFO_HTTP_VERSION]
		response['version'] = 'HTTP/1.1' if version == HTTP_VERSION.V1_1 else 'HTTP/1.0' if version == HTTP_VERSION.V1_0 else 'HTTP/2'
		#exit([response['version']])
		self.calculate_timmings(curl_info, response, request_sent_time_ms)
		exit(response)
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
		'''