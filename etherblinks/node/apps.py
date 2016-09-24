from __future__ import unicode_literals

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from datetime import datetime, timedelta

from django.apps import AppConfig
from django.conf import settings

from monitor import check_channel


def deferred_task(func):
    def inner_function(*args, **kwargs):
        run_date = datetime.now() + timedelta(seconds=10)
        scheduler.add_job(func, args=args, kwargs=kwargs, run_date=run_date)
    return inner_function


def async_task(func):
    def inner_function(*args, **kwargs):
        run_date = datetime.now()
        scheduler.add_job(func, args=args, kwargs=kwargs, run_date=run_date)
    return inner_function


def monitor_channel(micropayments_channel):
    scheduler.add_job(check_channel, 'interval', args=[micropayments_channel], minutes=settings.MONITORING_MINUTES)


class NodeConfig(AppConfig):
    name = 'node'

    def ready(self):
        from models import MicropaymentsChannel
        for channel in MicropaymentsChannel.objects.all():
            monitor_channel(channel)


logging.basicConfig()

scheduler = BackgroundScheduler()
scheduler.start()
