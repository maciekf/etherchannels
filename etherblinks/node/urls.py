from django.conf.urls import include, url

from . import views

urlpatterns = [
    url(r'^auth/register/$', views.register),
    url(r'^auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^channels/save/$', views.save_channel),
    url(r'^channels/create/$', views.create_channel),
    url(r'^channels/all/$', views.list_channels),
    url(r'^channels/(?P<cid>[0-9]+)/$', views.get_channel),
    url(r'^channels/(?P<cid>[0-9]+)/open/$', views.open_channel),
    url(r'^channels/(?P<cid>[0-9]+)/confirm/$', views.confirm_channel),
    url(r'^channels/(?P<cid>[0-9]+)/payment/send/$', views.update_channel),
    url(r'^channels/(?P<cid>[0-9]+)/payment/accept/$', views.accept_update_channel),
    url(r'^channels/(?P<cid>[0-9]+)/payment/confirm/$', views.confirm_update_channel),
]
