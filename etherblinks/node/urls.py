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
    url(r'^channels/(?P<cid>[0-9]+)/update/accept/$', views.accept_update_channel),
    url(r'^channels/(?P<cid>[0-9]+)/update/confirm/$', views.confirm_update_channel),
    url(r'^channels/(?P<cid>[0-9]+)/htlc/send/$', views.send_htlc),
    url(r'^channels/(?P<cid>[0-9]+)/htlc/accept/$', views.accept_htlc),
    url(r'^channels/(?P<cid>[0-9]+)/htlc/claim/$', views.claim_htlc_offline),
    url(r'^channels/(?P<cid>[0-9]+)/htlc/resolve/$', views.resolve_htlc_offline),
    url(r'^channels/(?P<cid>[0-9]+)/htlc/update/accept/$', views.accept_htlc_update),
    url(r'^channels/(?P<cid>[0-9]+)/sync/$', views.commit_update_channel),
    url(r'^channels/(?P<cid>[0-9]+)/lock/$', views.request_closing_channel),
    url(r'^channels/(?P<cid>[0-9]+)/close/$', views.close_channel),
    url(r'^channels/(?P<cid>[0-9]+)/withdraw/$', views.withdraw_from_channel),
]
