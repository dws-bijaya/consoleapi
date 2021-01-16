from easy_timezones.utils import is_valid_ip, is_local_ip
import requests
import json, os, sys

libs_loaded = None


def service_load_countries():
	from connections import SApiConnections
	redis_conn = SApiConnections._redis_conn()
	from settings import REDIS_COUNTRIES_KEY, COUNTRY_CACHE_FILE

	json_file = os.path.dirname(os.path.abspath(__file__)) + '/countries.json'
	if not os.path.exists(json_file):
		exit("Json No Reaady")

	with open(json_file, 'r') as p:
		json_data = json.load(p)
		redis_conn[0].delete(REDIS_COUNTRIES_KEY)
		hmset = {}
		for ccode in json_data:
			hmset[ccode] = json.dumps(json_data[ccode])
		redis_conn[0].hmset(REDIS_COUNTRIES_KEY, hmset)
	exit('success')
	#s = Settings('settings.py')
	#settings.configure()
	#REDIS_HOST = getattr(settings, "STATIC_ROOT", None)
	#exit([settings.STATIC_ROOT])


def service_update_country():
	from settings import COUNTRY_CACHE_FILE
	from xml.etree import ElementTree
	from bs4 import BeautifulSoup
	from io import StringIO
	import csv

	## load country phone  code
	country_phone_api = 'http://country.io/phone.json'
	country_phone_json = requests.get(country_phone_api, stream=False).json()
	if not country_phone_json:
		exit("Failed to find country's phone. Exiting")

	## load country phone  code
	country_api = 'https://raw.githubusercontent.com/annexare/Countries/master/dist/countries.emoji.min.json'
	countries_json = requests.get(country_api, stream=False).json()
	if not countries_json:
		exit("Failed to find country's details. Exiting")

	##### LOAD LANG+++
	language_api = 'https://raw.githubusercontent.com/annexare/Countries/master/dist/languages.all.min.json'
	languages_json = requests.get(language_api, stream=False).json()
	if not languages_json:
		exit("Failed to find country's language. Exiting")

	## LOAD COUNTRY CURRENCY CODE ###
	country_currency_api = 'https://gist.githubusercontent.com/HarishChaudhari/4680482/raw/b61a5bdf5f3d5c69399f9d9e592c4896fd0dc53c/country-code-to-currency-code-mapping.csv'
	response = requests.get(country_currency_api, stream=False)
	f = StringIO(response.text)
	country_continents = {"AF": "Africa", "AN": "Antarctica", "AS": "Asia", "EU": "Europe", "NA": "North America", "OC": "Oceania", "SA": "South America"}
	with open(os.path.dirname(os.path.abspath(__file__)) + '/currency-symbol-map.json') as p:
		currencymap = json.load(p)
		for ccode in countries_json:
			currency = countries_json[ccode]['currency'] if ccode in countries_json and 'currency' in countries_json[ccode] else None
			if currency:
				countries_json[ccode]['currency_symbol'] = currencymap[currency] if currency in currencymap else None
				del countries_json[ccode]['currency']
				countries_json[ccode]['currency_code'] = currency
			continent_code = countries_json[ccode]['continent']
			del countries_json[ccode]['continent']
			countries_json[ccode]['continent_code'] = continent_code
			countries_json[ccode]['continent_name'] = country_continents[continent_code]

			languages = countries_json[ccode]['languages'] if 'languages' in countries_json[ccode] else []
			languages = [dict({'code': language}, **languages_json[language]) for language in languages if language in languages_json]
			countries_json[ccode]['languages'] = languages
	################

	for cc in csv.reader(f, delimiter=',', quotechar='"'):
		if cc == ['Country', 'CountryCode', 'Currency', 'Code']:
			continue
		#
		ccode = cc[1]
		if ccode in countries_json:
			countries_json[ccode]['currency_name'] = cc[2]

	#exit(countries_json['IN'])

	with open(COUNTRY_CACHE_FILE, 'w') as p:
		json.dump(countries_json, p)
	#
	exit('Success')

	## Continent detail
	country_continent_api = 'https://pkgstore.datahub.io/JohnSnowLabs/country-and-continent-codes-list/country-and-continent-codes-list-csv_csv/data/b7876b7f496677669644f3d1069d3121/country-and-continent-codes-list-csv_csv.csv'
	response = requests.get(country_continent_api, stream=False)
	f = StringIO(response.text)
	country_continents = {}
	for cc in csv.reader(f, delimiter=',', quotechar='"'):
		if cc == ['Continent_Name', 'Continent_Code', 'Country_Name', 'Two_Letter_Country_Code', 'Three_Letter_Country_Code', 'Country_Number']:
			continue
		#
		country_continents[cc[3]] = {'code': cc[1], 'name': cc[0]}
	if not country_continents:
		exit("No cuntry with continent found.")
	#exit(country_continents['IN'])
	##

	##

	## LOAD COUNTRY EMOJI CODE ###
	emoji_url = 'https://apps.timwhitlock.info/emoji/tables/iso3166'
	response = requests.get(emoji_url, stream=False)
	soup = BeautifulSoup(response.text, 'html.parser')
	table_countries = soup.body.find('table', attrs={'class': 'table-striped'})
	if table_countries is None:
		exit("Failed to find countries. Exiting")

	fetch_columns = ['ISO', 'Emoji', 'Unicode', 'Name']
	fetch_headers = False
	emoji_countries = {}
	for row in table_countries.find_all('tr'):
		if fetch_headers is False:
			fetch_headers = [column.get_text() for column in row.find_all('th')]
			continue
		tds = row.find_all('td')
		ISO3166alpha2 = None
		country_emoji = {}
		for fetch_column in fetch_columns:
			idx = fetch_headers.index(fetch_column)
			if fetch_column == 'ISO':
				val = tds[idx].text.strip()
				ISO3166alpha2 = val

			if fetch_column == 'Emoji':
				val = tds[idx].find('span', attrs={'class': 'emoji'}).get_text()
				country_emoji['emoji'] = val

			if fetch_column == 'Unicode':
				val = tds[idx].find('a').get_text()
				country_emoji['emoji_unicode'] = val

		emoji_countries[ISO3166alpha2] = (country_emoji)
	#exit([emoji_countries])

	country_api = 'https://www.geonames.org/countries/'
	response = requests.get(country_api, stream=False)
	soup = BeautifulSoup(response.text, 'html.parser')
	#exit([soup.body])
	table_countries = soup.body.find('table', attrs={'id': 'countries'})
	if table_countries is None:
		exit("Failed to find countries. Exiting")

	#
	fetch_columns = ['ISO-3166alpha2', 'ISO-3166alpha3', 'ISO-3166numeric', 'Country', 'Capital', 'Continent']
	fetch_headers = False
	countries = {}

	for row in table_countries.find_all('tr'):
		if fetch_headers is False:
			fetch_headers = [column.get_text() for column in row.find_all('th')]
			continue
		tds = row.find_all('td')
		country_data = {}
		ISO3166alpha2 = None
		for fetch_column in fetch_columns:
			idx = fetch_headers.index(fetch_column)
			val = tds[idx].get_text()
			if fetch_column == 'ISO-3166alpha2':
				ISO3166alpha2 = val
			country_data[fetch_column] = val
		countries[ISO3166alpha2] = (country_data)
		countries[ISO3166alpha2]['currency'] = country_currency[ISO3166alpha2] if ISO3166alpha2 in country_currency else None
		countries[ISO3166alpha2]['emoji'] = emoji_countries[ISO3166alpha2] if ISO3166alpha2 in emoji_countries else None
		if 'Continent' in countries[ISO3166alpha2]:
			del countries[ISO3166alpha2]['Continent']
		#
		countries[ISO3166alpha2]['continent_name'] = country_continents[ISO3166alpha2]['name'] if ISO3166alpha2 in country_continents else None
		countries[ISO3166alpha2]['continent_code'] = country_continents[ISO3166alpha2]['code'] if ISO3166alpha2 in country_continents else None
		countries[ISO3166alpha2]['calling_code'] = country_phone_json[ISO3166alpha2] if ISO3166alpha2 in country_phone_json else None

	exit(countries['IN'])
	#exit(countries)
	exit(countries)
	# Fill


def get_contry_detail(ccode: str):
	from settings import REDIS_COUNTRIES_KEY, COUNTRY_CACHE_FILE
	from connections import SApiConnections
	redis_conn = SApiConnections._redis_conn()
	try:
		cdata = redis_conn[0].hget(REDIS_COUNTRIES_KEY, ccode)
		if cdata:
			return json.loads(cdata)
	except Exception as e:
		pass
	try:
		with open(COUNTRY_CACHE_FILE, 'r') as p:
			cdata = json.load(p)
			return cdata[ccode] if ccode in cdata else {}
	except Exception as e:
		pass
	return {}


def ip_detail(ip: any):
	global libs_loaded
	'''
		curl ipinfo.io/{ip}/json
		http://api.ipinfodb.com/v3/ip-city/?key=YOUR_API_KEY=642277301a233138b250325df80db0c500346e0c88a7d4df100320ab91f9aafd&ip=IP_V4_OR_IPV6_ADDRESS
		http://api.ipstack.com/182.64.187.71?access_key=1ae7c8cc57dc63a22e6ec4d7160876cd&format=1
		https://assets.ipstack.com/flags/in.svg
		https://geolocation-db.com/json/182.64.187.71&position=true
	'''
	class ipapi:
		@classmethod
		def country_pack(self: object, ccode: str, context: dict):
			country_data = get_contry_detail(ccode)

			#
			context['continent_code'] = country_data['continent_code'] if 'continent_code' in country_data else None
			context['continent_name'] = country_data['continent_name'] if 'continent_name' in country_data else None

			#
			context['country_code'] = ccode
			context['country_name'] = country_data['name'] if 'continent_name' in country_data else None
			context['country_capital'] = country_data['capital'] if 'capital' in country_data else None
			context['country_native'] = country_data['native'] if 'native' in country_data else None
			context['country_phone'] = country_data['phone'] if 'phone' in country_data else None
			context['country_languages'] = country_data['languages'] if 'languages' in country_data else None
			context['country_currency_emoji'] = country_data['emoji'] if 'emoji' in country_data else None
			context['country_currency_emojiU'] = country_data['emojiU'] if 'emojiU' in country_data else None
			context['country_currency_symbol'] = country_data['currency_symbol'] if 'currency_symbol' in country_data else None
			context['country_currency_code'] = country_data['currency_code'] if 'currency_code' in country_data else None
			context['country_currency_name'] = country_data['currency_name'] if 'currency_name' in country_data else None

	class ipstack_com(ipapi):
		api_url = 'http://api.ipstack.com/{qry_ip}?access_key=1ae7c8cc57dc63a22e6ec4d7160876cd&format=1'

		@classmethod
		def fetch(self, qry_ip: any, context: dict):
			endpoint = self.api_url.format(qry_ip=qry_ip)
			try:
				#response = requests.get(endpoint).json()
				response = {
				    'ip': '182.64.187.71',
				    'type': 'ipv4',
				    'continent_code': 'AS',
				    'continent_name': 'Asia',
				    'country_code': 'IN',
				    'country_name': 'India',
				    'region_code': 'DL',
				    'region_name': 'Delhi',
				    'city': 'New Delhi',
				    'zip': '110101',
				    'latitude': 28.626230239868164,
				    'longitude': 77.21807861328125,
				    'location': {
				        'geoname_id': 1261481,
				        'capital': 'New Delhi',
				        'languages': [{
				            'code': 'hi',
				            'name': 'Hindi',
				            'native': 'हिन्दी'
				        }, {
				            'code': 'en',
				            'name': 'English',
				            'native': 'English'
				        }],
				        'country_flag': 'http://assets.ipstack.com/flags/in.svg',
				        'country_flag_emoji': '🇮🇳',
				        'country_flag_emoji_unicode': 'U+1F1EE U+1F1F3',
				        'calling_code': '91',
				        'is_eu': False
				    }
				}

				#
				country_code = response['country_code']
				self.country_pack(country_code, context)
				#exit(context)

				context['region_code'] = response['region_code']
				context['region_name'] = response['region_name']
				context['city'] = response['city']
				context['zip'] = response['zip']
				context['latitude'] = response['latitude']
				context['longitude'] = response['longitude']

			except Exception as e:
				raise e
				pass

			return False

	class ipinfo_io:
		api_url = 'http://ipinfo.io/{ip}/json'

		def fetch(ip: any, context: dict):
			pass

	class ipinfodb_com:
		pass

	class geolocation_db_com:
		pass

	if not libs_loaded:
		libs_loaded = [ipstack_com]  #, ipinfodb_com(), ipstack_com(), geolocation_db_com()]

	lib = libs_loaded[0]

	context = {'hostname': None}
	context['city'] = None
	context['region_code'] = None
	context['region_name'] = None

	#
	context['continent_code'] = None
	context['continent_name'] = None
	#
	context['country_code'] = None
	context['country_name'] = None
	context['country_capital'] = None
	context['country_native'] = None
	context['country_phone'] = None
	context['country_languages'] = []
	context['country_emoji'] = None
	context['country_emojiU'] = None
	context['country_currency_symbol'] = None
	context['country_currency_code'] = None
	context['country_currency_name'] = None

	#
	context['state'] = None
	context['latitude'] = None
	context['longitude'] = None
	context['zip'] = None
	context['timezone'] = None
	context['is_eu'] = None
	#
	return lib.fetch(ip, context)
	pass


def get_ip_address_from_request(request):
	""" Makes the best attempt to get the client's real IP or return the loopback """
	PRIVATE_IPS_PREFIX = ('10.', '172.', '192.', '127.')
	ip_address = ''
	x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
	if x_forwarded_for and ',' not in x_forwarded_for:
		if not x_forwarded_for.startswith(PRIVATE_IPS_PREFIX) and is_valid_ip(x_forwarded_for):
			ip_address = x_forwarded_for.strip()
	else:
		ips = [ip.strip() for ip in x_forwarded_for.split(',')]
		for ip in ips:
			if ip.startswith(PRIVATE_IPS_PREFIX):
				continue
			elif not is_valid_ip(ip):
				continue
			else:
				ip_address = ip
				break
	if not ip_address:
		x_real_ip = request.META.get('HTTP_X_REAL_IP', '')
		if x_real_ip:
			if not x_real_ip.startswith(PRIVATE_IPS_PREFIX) and is_valid_ip(x_real_ip):
				ip_address = x_real_ip.strip()
	if not ip_address:
		remote_addr = request.META.get('REMOTE_ADDR', '')
		if remote_addr:
			if not remote_addr.startswith(PRIVATE_IPS_PREFIX) and is_valid_ip(remote_addr):
				ip_address = remote_addr.strip()
	if not ip_address:
		ip_address = '127.0.0.1'
	return ip_address
