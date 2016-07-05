from __future__ import unicode_literals

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from datetime import datetime, timedelta

from django.apps import AppConfig


logging.basicConfig()

scheduler = BackgroundScheduler()
scheduler.start()


def deferred_task(func):
    def inner_function(*args, **kwargs):
        run_date = datetime.now() + timedelta(seconds=10)
        scheduler.add_job(func, args=args, kwargs=kwargs, run_date=run_date)
    return inner_function


class NodeConfig(AppConfig):
    name = 'node'
