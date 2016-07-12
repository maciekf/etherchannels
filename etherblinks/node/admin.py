from django.contrib import admin

from models import ChannelState, HashedTimelockContract, Location, MicropaymentsChannel, UserAddress

admin.site.register(ChannelState)
admin.site.register(HashedTimelockContract)
admin.site.register(Location)
admin.site.register(MicropaymentsChannel)
admin.site.register(UserAddress)
