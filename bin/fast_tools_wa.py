import re
from urllib.parse import quote


class ERROR_CODES:
	OK = (0x0, '+OK')
	UNKNONWN = (0x1, 'Unknown error.')
	MALFORM_URL = (0x2, 'Malform error.')
	WRONG_HTTP_VERSION = (0x3, 'Invalid HTTP version.')
	INVALID_RESOLVE_IP = (0x4, 'Invalid Resolve IP.')

	@classmethod
	def new(self, Err_No: int, Err_Msg: str):
		return (Err_No if Err_No is not None else 1, Err_Msg)


class WA:
	@classmethod
	def direct_msg(self, request, mobno: str, msg: str):
		mobno = re.sub("[^0-9]", "", mobno)
		msg = quote(msg)

		response = {}
		response['errno'], response['errmsg'] = ERROR_CODES.OK
		#response['waos'] =
		response['wa_url'] = "https://web.whatsapp.com/send?phone={phone}&text={text}".format(phone=mobno, text=msg)
		response['wa_url2'] = "https://api.whatsapp.com/send?phone={phone}&text={text}".format(phone=mobno, text=msg)
		response['wa_url3'] = "https://wa.me/{phone}/?text={text}".format(phone=mobno, text=msg)
		response['wa_protocol'] = 'whatsapp://send/?phone={phone}&text={text}'.format(phone=mobno, text=msg)

		#response['wa_ismobile'] = request.user_agent.is_mobile
		#response['wa_istablet'] = request.user_agent.is_tablet
		#response['wa_osfamily'] = request.user_agent.os.family
		#
		#response['wa_url2'] = request.user_agent.os.family
		response['wa_supported'] = True if (request.user_agent.is_mobile or request.user_agent.is_tablet) and (request.user_agent.os.family == 'Android' or request.user_agent.device.family == 'iPhone') else False

		return response