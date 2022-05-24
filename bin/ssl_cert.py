from operator import ipow
import re
from urllib.parse import urlparse
import socket
import ipaddress
import ssl
import OpenSSL
import time
import hashlib
import base64
from cryptography.hazmat.primitives import serialization
import datetime



class SSL_Cert_Error:
	OK = (0, '+OK')
	INVALID_PORT = (1, 'Invalid port.')
	INVALID_DOMAIN_OR_IP = (2, 'Invalid domain or ip.')
	INVALID_RESOLVE_IP = (3, 'Invalid resolve ip.')
	FAIL_TO_GET = (4, 'Failed to get cert.')
	FAIL_TO_GET_DOMAIN_IP = (4, 'Failed to get domain ip.')


class SSL_Cert_Engine:

	@staticmethod
	def validate(domain_ip, port=None, resolve_ip=None):
		try:
			port = int(port)
		except:
			pass

		# domain_ip = "127.0.0.1"
		parse_port = None
		try:
			p = urlparse(domain_ip)
			domain_ip = p.netloc if p.netloc else p.path
			domain_ip_port = domain_ip.split(":")
			domain_ip = domain_ip_port[0]
			parse_port = domain_ip_port[1] if len(domain_ip_port) > 1 else None
		except:
			domain_ip = None

		if not domain_ip:
			return SSL_Cert_Error.INVALID_DOMAIN + (None, )

		ip4_req = True
		# exit([domain_ip, parse_port])
		is_domain = False
		try:
			ipaddr = ipaddress.ip_network(domain_ip, True)
			if isinstance(ipaddr, ipaddress.IPv6Network):
				ip4_req = False
			resolve_ip = None
		except:
			pattern = '^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][-_\.a-zA-Z0-9]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$'
			matched = re.match(pattern, domain_ip)
			if not matched:
				return SSL_Cert_Error.INVALID_DOMAIN_OR_IP + (None, )
			is_domain = True

		port = int(parse_port if parse_port else 443 if not port else port)
		if not (port > 0 and port < 1000000):
			return SSL_Cert_Error.INVALID_PORT + (None, )

		if resolve_ip:
			try:
				ipaddr = ipaddress.ip_network(resolve_ip, True)
				if isinstance(ipaddr, ipaddress.IPv6Network):
					ip4_req = False
			except:
				return SSL_Cert_Error.INVALID_RESOLVE_IP + (None, )

		if is_domain and not resolve_ip:
			try:
				data = socket.gethostbyname(domain_ip)
				resolve_ip = (data)
			except Exception:
				return SSL_Cert_Error.FAIL_TO_GET + (None, )
		print("Conecting ... %s:%s using server_hostname = %s" %
			  (resolve_ip if resolve_ip else domain_ip, port, domain_ip))
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		cert = None
		tooks = 0.0
		try:
			start = time.process_time()
			conn = socket.create_connection(
				(resolve_ip if resolve_ip else domain_ip, port), timeout=5.0)
			sock = context.wrap_socket(conn, server_hostname=domain_ip)
			der_cert = sock.getpeercert(True)
			tooks = time.process_time() - start
			sock.close()
			cert = ssl.DER_cert_to_PEM_cert(der_cert)
			x509 = OpenSSL.crypto.load_certificate(
				OpenSSL.crypto.FILETYPE_PEM, cert)
		except Exception as e:
			x509 = None

		if not x509:
			return SSL_Cert_Error.FAIL_TO_GET + (None, )

		pcert = ((x509.get_pubkey().to_cryptography_key().public_bytes(
			encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)))
		pin_sha256 = base64.b64encode((hashlib.sha256(base64.b64decode(
			''.join(pcert.decode().split("\n")[1:-2]))).digest())).decode()

		expd_cmonth, expd_nmonth, expd_wday, expd_nyear, left_days = ("N/a", "N/a", "N/a", "N/a", "-1")
		try:
			expiry_date = datetime.datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%S%z')
			expd_cmonth =  expiry_date.strftime("%B")
			expd_nmonth =  expiry_date.strftime("%m")
			expd_wday =  expiry_date.strftime("%A")
			expd_nday =  expiry_date.strftime("%d")
			expd_nyear =  expiry_date.strftime("%Y")
			delta = expiry_date - datetime.datetime.now(datetime.timezone.utc)
			left_days = str(delta.days)
		except:
			pass


		subject = dict(x509.get_subject().get_components())
		issuer = dict(x509.get_issuer().get_components())
		serial_number = '{0:x}'.format(int(x509.get_serial_number()))
		signature_algorithm = x509.get_signature_algorithm().decode()
		repsp = { 'exp_date' : {  'left_days': left_days,  'nday': expd_nday,  'cmonth': expd_cmonth,  'nmonth' : expd_nmonth, 'wday': expd_wday, 'nyear': expd_nyear},  'common_name': subject[b'CN'].decode(), 'pin_sha256': pin_sha256, 'signature_algorithm': signature_algorithm, 'serial_number': serial_number, 'issuer': {'common_name': issuer[b'CN'].decode()}, 'has_expired': x509.has_expired(), "tooks": tooks,
				 "check_on": time.time(), 'remote_ip': resolve_ip, 'domain_ip': domain_ip, "ip4_req": ip4_req, "port": port if port else None}
		return SSL_Cert_Error.OK + (repsp, )
