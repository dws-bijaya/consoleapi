from bin.fast_tools_smtp import Smtp

import smtplib

params = {
    "server_type": "server_gmail",
    "access_token": "ya29.a0ARrdaM_nxV1sLEKAF4vIJPELEwQtuJuR1NPJrDzbPYC8tOszRYq5NK3wwgNYnDPMvI54xN8RuY4czUNo5Pwh3mOLNfnfQVy1loU2KueYCUi1dlJ_t8TsGioOMu5i83YCX33voWzPjvxxk2VmT5Ml0KndIOpgYA",
    "refresh_token": "1//045CXuBsiLaLSCgYIARAAGAQSNwF-L9IrGrCPp2DeAJ8F_1xTszB1uCI7BmFlchBc4B_99eLkhKUNBqTqaENUZi14XVV83ApzOl0",
    "auth": {
        "username": "790375977785-rt7olm5j00tin07nkcofr890hs2fpme7.apps.googleusercontent.com",
        "password": "fMk_2zj0onucVSkfk0UmFpMr"
    },
    "libray": "google-api-python-client",
    "from_address": "Bijaya Kumar <bijaya@tickethuddle.com>",
    "to_address": ["Bijaya Behera <it.bijaya@gmail.com>"],
    "bcc_address": [],
    "cc_address": [],
    "subject": "Test subject",
    "body": "<p><b>Test subject</b></p>",
    "format": 'html_text'
}

response = Smtp.Send(params)
import json
exit([response])

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
