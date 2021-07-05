from django.http import HttpResponse, HttpRequest
from django.template import loader


class default:
	def index(request):
		template = loader.get_template('default/index.html')
		context = {'meta_title': 'Free tools for testing almost all eveythings on sweet single interface'}
		context['meta_description'] = "Developer's single sweet single interface for testing"
		return HttpResponse(template.render())
		pass