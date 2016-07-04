from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^channel/', views.create_channel),
]
