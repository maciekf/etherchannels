from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.db import models


class UserAddress(models.Model):
    user = models.ForeignKey(User)
    address = models.CharField(max_length=100, unique=True)

    @classmethod
    def create(cls, user, address):
        return cls(user=user, address=address)


class MicropaymentsChannel(models.Model):
    channel_id = models.CharField(max_length=100, primary_key=True)

    owner = models.ForeignKey(User)


class ChannelState(models.Model):
    channel = models.ForeignKey(MicropaymentsChannel)

    balance_timestamp = models.CharField(max_length=100)
    from_balance = models.CharField(max_length=100)
    to_balance = models.CharField(max_length=100)

    second_signature = models.CharField(max_length=150)


class HashedTimelockContract(models.Model):
    channel = models.ForeignKey(MicropaymentsChannel)

    balance_timestamp = models.CharField(max_length=100)
    timeout = models.CharField(max_length=100)
    contract_hash = models.CharField(max_length=100)
    from_to_delta = models.CharField(max_length=100)
    data = models.CharField(max_length=100)

    second_signature = models.CharField(max_length=150)
