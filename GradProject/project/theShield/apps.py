from django.apps import AppConfig
from suit.apps import DjangoSuitConfig

class TheshieldConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'theShield'

#class SuitConfig(DjangoSuitConfig):
    #layout = 'horizontal'
    #layout = 'vertical'
    