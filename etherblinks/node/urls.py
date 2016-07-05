from django.conf.urls import include, url

from . import views

urlpatterns = [
    url(r'^auth/register', views.register),
    url(r'^auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^channels/', views.create_channel),
]
