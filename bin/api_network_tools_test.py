from api_network_tools import ip_detail, service_update_country, service_load_countries, get_contry_detail


def test_ip_detail():
	#
	exit(ip_detail('182.64.187.71'))


def test_service_update_country():
	exit(service_update_country())


#
def test_service_load_countries():
	exit(service_load_countries())


#
def test_load_country():
	exit(get_contry_detail('IN'))


import sys, os
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/bin/')

if __name__ == "__main__":

	globals()[sys.argv[1]]()