from __future__ import unicode_literals

from django.db import models


class MicropaymentsChannel(models.Model):
    channel_id = models.CharField(max_length=70)
    channel_address = models.CharField(max_length=70)

    from_address = models.CharField(max_length=70)
    from_balance = models.CharField(max_length=70)

    to_address = models.CharField(max_length=70)
    to_balance = models.CharField(max_length=70)

    balance_timestamp = models.CharField(max_length=70)
    balance_signature = models.CharField(max_length=140)
