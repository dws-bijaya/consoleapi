import re
from email.parser import BytesParser, Parser
from email.policy import default
from email.message import EmailMessage
from email.headerregistry import Address
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import smtplib
import tempfile
import smtplib
import os
import sys
from io import StringIO


class ERROR_CODES:
    OK = (0x0, '+OK')
    SMTPSuccess = (200, '+OK')
    UNKNONWN = (0x1, 'Unknown error.')
    MALFORM_HOST = (0x2, 'Malform host.')
    MALFORM_PORT = (0x3, 'Malform port or port not in range (1-9999999).')
    MALFORM_FROM_EMAILADDRESS = (0x3, 'Malform FROM email address.')
    MALFORM_TO_EMAILADDRESS = (0x4, 'Malform TO email address.')
    MALFORM_BCC_EMAILADDRESS = (0x5, 'Malform BCC email address.')
    MALFORM_CC_EMAILADDRESS = (0x6, 'Malform CC email address.')
    INVALID_MAIL_FORMAT = (0x7, 'Invalid Mail format.')
    INVALID_CLIENTLIBRAY = (0x7, 'Invalid client libray selected.')
    SMTPException = (8, 'SMTP Exception has occured.')
    SMTPServerDisconnected = (8, 'SMTP Server disconnected.')
    SMTPResponseException = (9, 'SMTP Response Exception.')
    SMTPSenderRefused = (10, 'SMTP Sender Refused.')
    SMTPRecipientsRefused = (11, 'SMTP recipients refused.')
    SMTPDataError = (12, 'SMTP Data Error.')
    SMTPConnectError = (13, 'SMTP Connect Error.')
    SMTPHeloError = (14, 'SMTP Helo Error.')
    SMTPAuthenticationError = (15, 'SMTP Authentication Error.')
    INVALID_UESERAUTH = (16, 'SMTP Authentication Error.')
    CATCHAALL_1000_Error = (1000, 'SMTP Helo Error.')

    # WRONG_HTTP_VERSION = (0x3, 'Invalid HTTP version.')
    # INVALID_RESOLVE_IP = (0x4, 'Invalid Resolve IP.')

    @classmethod
    def new(self, Err_No: int, Err_Msg: str):
        return (Err_No if Err_No is not None else 1, Err_Msg)


class Server_Smtp:
    @classmethod
    def parse_output(self, output):
        arr_output = []
        connect = False
        msgid = None
        try:
            for line in output.decode('utf-8').split("\n"):
                if line.startswith("reply: retcode"):
                    continue
                elif line.startswith("connect:"):
                    if connect:
                        continue
                    connect = True
                    line = line[9:]
                    continue

                elif line.startswith("reply:"):
                    line = line[7:]
                elif line.startswith("send:"):
                    line = line[6:]
                elif line.startswith("data:"):
                    line = line[6:]
                elif not line:
                    continue
                else:
                    pass

                if line.startswith("("):
                    continue

                if line.startswith("b'"):
                    line = line[2:]

                if msgid is None and line.find(' OK id=') >= 1:
                    msgid = line.split(' OK id=')[0]

                line = line.strip().strip("'").strip('\\n').strip('\\r')
                if line.startswith("MIME-Version:"):
                    arr_output.extend(line.split('\\r\\n'))
                else:
                    arr_output.append(line)
                # print("{:3} {}".format(1, line))
            # print(arr_output)
            # exit()
        except Exception as e:
            pass

        return arr_output

    @classmethod
    def send_via_smtplib(self, host, port, timeout, secure, starttls, verify, auth, msg):

        import smtplib
        import ssl
        context = ssl._create_unverified_context()

        # auth['username'] = "eee"
        # host = '182.98.2.1'
        response = Smtp.default_response()
        debug = 1
        try:
            if debug:
                '''
                t = tempfile.TemporaryFile()
                available_fd = t.fileno()
                t.close()
                PrevOutFD = os.dup(2)
                os.dup2(2, available_fd)
                t = tempfile.TemporaryFile()
                os.dup2(t.fileno(), 2)
                '''
                old_stderr = sys.stderr
                redirected_error = sys.stderr = StringIO()
                debug = 2

            if secure != 'ssl':
                server = smtplib.SMTP(host, port, timeout=timeout)
            else:
                server = smtplib.SMTP_SSL(
                    host, port, timeout=timeout, context=context if not verify else None)

            server.set_debuglevel(1)
            res = server.connect(host, port)
            # print(res, file=sys.stderr)
            if secure == 'tls' or starttls:
                server.ehlo('182.168.1.1')
                server.starttls(context=context if not verify else None)
                server.ehlo()
            if auth:
                server.login(auth['username'], auth['password'])

            from_addr = str(msg['From'])
            to_addr = str(msg['To'])
            # svr_resp = server.sendmail(from_addr, to_addr, msg.as_string())
            svr_resp = server.send_message(msg)
            server.quit()

            if debug == 2:
                try:
                    console_out = []
                    stderr_output = redirected_error.getvalue().encode()
                    console_out = self.parse_output(stderr_output)
                    sys.stderr = old_stderr
                    redirected_error.close()
                    debug = 0
                except Exception as e:
                    pass

            if svr_resp:
                if isinstance(svr_resp, dict):
                    try:
                        errno, errmsg = list(svr_resp.items())[0][1]
                        response['errno'], response['errmsg'] = ERROR_CODES.new(
                            errno, errmsg)
                        return response
                    except Exception as e:
                        pass
                response['errno'], response['errmsg'] = ERROR_CODES.UNKNONWN
            else:
                response['errno'], response['errmsg'] = ERROR_CODES.SMTPSuccess
                console_out.insert(0, "Connected to smtp://{0}:{1}/?starttls={2}&ssl={3}".format(
                    host, port, "2", "1" if secure == 'ssl' else '0'))
                response['output'] = console_out
            # exit([response])
            return response
        except smtplib.SMTPNotSupportedError as e:
            if debug == 2:
                try:
                    sys.stderr = old_stderr
                    redirected_error.close()
                except Exception as e:
                    pass
            response['errno'], response['errmsg'] = ERROR_CODES.SMTPNotSupportedError
            return response
        except smtplib.SMTPRecipientsRefused as e:
            if debug == 2:
                try:
                    sys.stderr = old_stderr
                    redirected_error.close()
                except Exception as e:
                    pass
            response['errno'], response['errmsg'] = ERROR_CODES.SMTPRecipientsRefused
            return response
        except smtplib.SMTPServerDisconnected as e:
            if debug == 2:
                try:
                    sys.stderr = old_stderr
                    redirected_error.close()
                except Exception as e:
                    pass
            response['errno'], response['errmsg'] = ERROR_CODES.SMTPServerDisconnected
            return response
        except (smtplib.SMTPNotSupportedError, smtplib.SMTPAuthenticationError, smtplib.SMTPServerDisconnected, smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError, smtplib.SMTPAuthenticationError,
                smtplib.SMTPHeloError) as e:
            if debug == 2:
                try:
                    sys.stderr = old_stderr
                    redirected_error.close()
                except Exception as e:
                    pass
            smtp_code = e.smtp_code if hasattr(e, 'smtp_code') and e.smtp_code is not None else (
                ERROR_CODES.CATCHAALL_1000_Error[0] + e.errno) if hasattr(e, 'errno') and e.errno is not None else ERROR_CODES.CATCHAALL_1000_Error[0]
            # exit([smtp_code, hasattr(e, 'smtp_code'), hasattr(e, 'errno'), e.errno])
            smtp_error = e.smtp_error.decode() if hasattr(e, 'smtp_error') and e.smtp_error is not None else (
                e.message) if hasattr(e, 'message') and e.message is not None else e.strerror if hasattr(e, 'strerror') and e.strerror is not None else ERROR_CODES.CATCHAALL_1000_Error[1]
            response['errno'], response['errmsg'] = ERROR_CODES.new(
                smtp_code, smtp_error)
            return response
        except Exception as e:
            if debug == 2:
                try:
                    sys.stderr = old_stderr
                    redirected_error.close()
                except Exception as e:
                    pass
            errno = ERROR_CODES.CATCHAALL_1000_Error[0] if not hasattr(
                e, 'errno') or e.errno is None else (ERROR_CODES.CATCHAALL_1000_Error[0] + e.errno)
            errmsg = e.message if hasattr(e, 'message') and e.message is not None else e.strerror if hasattr(
                e, 'strerror') and e.strerror else repr(e)
            response['errno'], response['errmsg'] = ERROR_CODES.new(
                errno, errmsg)
            if e == socket.timeout:
                response['errmsg'] = 'Timeout errr'
            return response

    @classmethod
    def send(self, response, libray, host, port, secure, starttls, verify, auth, from_addrs, to_addrs, bcc_addrs, cc_addrs, subject, body_html, body_text):
        if libray not in ['smtplib_py']:
            response['errno'], response['errmsg'] = ERROR_CODES.INVALID_CLIENTLIBRAY
            return response

        try:
            msg = EmailMessage()
            # exit([msg['From'], msg['To'], msg['Bcc'], msg['Cc']])
            if body_html and body_text:
                msg = EmailMessage()
                msg.set_content(body_text)
                msg.add_alternative(body_html, subtype='html')
                # msg.set_boundary('===============8344679239724483684CONSOLEPAI==')
            elif body_html:
                msg = EmailMessage()
                msg.add_header('Content-Type', 'text/html')
                msg.set_content(body_html, subtype='html')
            else:
                msg = EmailMessage()
                msg.add_header('Content-Type', 'text/plain')
                msg.set_content(body_text, subtype='plain')

            msg['Subject'] = subject
            msg['From'] = Address(from_addrs['display_name'],
                                  from_addrs['username'], from_addrs['domain'])
            msg['To'] = (Address(to_adr['display_name'], to_adr['username'],
                                 to_adr['domain']) for to_adr in to_addrs)
            if cc_addrs:
                msg['Cc'] = (Address(cc_addr['display_name'], cc_addr['username'],
                                     cc_addr['domain']) for cc_addr in cc_addrs)
            if bcc_addrs:
                msg['Bcc'] = (Address(bcc_addr['display_name'], bcc_addr['username'],
                                      bcc_addr['domain']) for bcc_addr in bcc_addrs)
            # msg['Bcc'] = ""
            # exit([msg.as_string()])
        except Exception as e:
            # raise e
            response['errno'], response['errmsg'] = ERROR_CODES.UNKNONWN
            return response

        timeout = 10
        response = self.send_via_smtplib(
            host, port, timeout, secure, starttls, verify, auth, msg)
        # exit([response])
        return response


class Smtp:
    LIBS_ALLOWED = ['server_smtp']

    @classmethod
    def build_emailaddresses(self, emailids):
        emailaddresses = []
        for emailid in emailids:
            stremail = 'From: {0}\n'.format(emailid)
            try:
                headers = Parser(policy=default).parsestr(stremail)
                display_name, email_domain = headers['From'].addresses[
                    0].display_name, headers['From'].addresses[0].domain
                if not headers['From'].addresses[0].username or not email_domain:
                    return None
                emailaddresses.append({'display_name': display_name, 'username': headers['From'].addresses[0].username,
                                       'domain': email_domain, 'address': '{0}@{1}'.format(headers['From'].addresses[0].username, email_domain)})
                # xit([display_name, email_domain])
            except Exception as e:
                # raise e
                return None
        return emailaddresses

    @classmethod
    def default_response(self):
        response = {}
        response['errno'], response['errmsg'] = ERROR_CODES.UNKNONWN
        response['ouput'] = []
        return response

    @classmethod
    def get_text(self, body_html):
        try:
            import html2text
            return html2text.html2text(body_html)
        except Exception as e:
            pass
        return ''

    @classmethod
    def _send(self):
        pass

    @classmethod
    def Send(self, params):

        response = self.default_response()
        # response['errno'], response['errmsg'] = ERROR_CODES.SMTPSuccess
        # return response
        server_type = params['server_type'].lower(
        ) if 'server_type' in params else None
        # exit([server_type])
        if server_type not in self.LIBS_ALLOWED:
            return response

        host = params['host'] if 'host' in params else ''
        # host = '193.234.4.3'
        port = params['port'] if 'port' in params else ''
        secure = params['secure'].lower() if 'secure' in params else ''
        auth = params['auth'] if 'auth' in params else {}
        libray = params['libray'] if 'libray' in params else None

        if auth and ('username' not in auth or 'password' not in auth or auth['username'] is None or auth['password'] is None):
            response['errno'], response['errmsg'] = ERROR_CODES.INVALID_UESERAUTH
            return response

        # username = params['username'] if 'username' in params else ''
        # password = params['password'] if 'password' in params else ''

        if server_type == 'server_smtp':
            """
            if not (re.search('^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$', host)
                            or re.search('^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$', host)) or host in ['localhost', '127.0.0.1', '0.0.0.0']:
                    response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_HOST
                    return response
            """
            if not re.search(r"^(?:(?:(?:[a-zA-z\-]+)\:\/{1,3})?(?:[a-zA-Z0-9])(?:[a-zA-Z0-9\-\.]){1,61}(?:\.[a-zA-Z]{2,})+|\[(?:(?:(?:[a-fA-F0-9]){1,4})(?::(?:[a-fA-F0-9]){1,4}){7}|::1|::)\]|(?:(?:[0-9]{1,3})(?:\.[0-9]{1,3}){3}))(?:\:[0-9]{1,5})?$", host) or host in ['localhost', '127.0.0.1', '0.0.0.0']:
                response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_HOST
                return response
            try:
                port = int(port)
            except Exception as e:
                port = -1

            if port <= 0 or port >= 9999999:
                response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_PORT
                return response

            if secure not in ['unsecured', 'ssl', 'tls']:
                response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_HOST
                return response

            starttls = params['starttls'] if 'starttls' in params else False
            verify = params['verify'] if 'verify' in params else False

            # exit('+OK')
        # if( !( g.test(host) || /^((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*::((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*|((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4})){7}$/g.test(host) || /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/g.test(host)))

        from_addrs = self.build_emailaddresses(
            [params['from_address'] if 'from_address' in params else ''])
        if from_addrs is None:
            response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_EMAILADDRESS
            return response

        # exit([from_adrs])
        to_addrs = self.build_emailaddresses(
            params['to_address'] if 'to_address' in params else '')
        if to_addrs is None:
            response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_TO_EMAILADDRESS
            return response

        #
        bcc_address = params['bcc_address'] if 'bcc_address' in params else []
        cc_addresses = params['cc_address'] if 'cc_address' in params else []
        bcc_addrs, cc_addrs = ([], [])
        if bcc_address:
            bcc_addrs = self.build_emailaddresses(bcc_address)
            if bcc_addrs is None:
                response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_BCC_EMAILADDRESS
                return response

        if cc_addresses:
            cc_addrs = self.build_emailaddresses(cc_addresses)
            if cc_addrs is None:
                response['errno'], response['errmsg'] = ERROR_CODES.MALFORM_CC_EMAILADDRESS
                return response

        from_addrs = from_addrs[0]
        # exit([from_addrs, to_addrs, bcc_addrs, cc_addrs])

        format = params['format'].lower() if 'format' in params else None
        if format not in ['html_text', 'html_only', 'text_only']:
            response['errno'], response['errmsg'] = ERROR_CODES.INVALID_MAIL_FORMAT
            return response

        subject = params['subject'] if 'subject' in params else 'Test Subject'
        body_html = params['body'] if 'body' in params else ''
        body_text = self.get_text(
            body_html) if format == 'html_text' else body_html if format == 'text_only' else None
        if format == 'text_only':
            body_html = None

        # exit([body_html, body_text])
        if server_type == 'server_smtp':
            return Server_Smtp.send(response, libray, host, port, secure, starttls, verify, auth, from_addrs, to_addrs, bcc_addrs, cc_addrs, subject, body_html, body_text)
