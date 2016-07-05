from django.conf.urls import include, url

from . import views

urlpatterns = [
    url(r'^auth/register/$', views.register),
    url(r'^auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^channels/$', views.create_channel),
    url(r'^channels/accept/$', views.register_created_channel),
    url(r'^channels/all/$', views.list_channels),
    url(r'^channels/(?P<cid>[0-9]+)/open/$', views.open_channel),
    url(r'^channels/(?P<cid>[0-9]+)/confirm/$', views.confirm_channel),
]
