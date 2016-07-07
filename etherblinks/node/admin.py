from django.contrib import admin
from models import ChannelState, Location, MicropaymentsChannel, UserAddress

admin.site.register(ChannelState)
admin.site.register(Location)
admin.site.register(MicropaymentsChannel)
admin.site.register(UserAddress)
