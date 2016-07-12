from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.db import models


class UserAddress(models.Model):
    user = models.OneToOneField(User)
    address = models.CharField(max_length=100, unique=True)

    @classmethod
    def create(cls, user, address):
        return cls(user=user, address=address)

    def __unicode__(self):
        return "[user=%s, address=%s]" % (self.user, self.address)


class Location(models.Model):
    hostname = models.CharField(max_length=100)
    port = models.IntegerField()

    @classmethod
    def create(cls, hostname, port):
        return cls(hostname=hostname, port=port)

    def __unicode__(self):
        return "[hostname=%s, port=%s]" % (self.hostname, self.port)


class MicropaymentsChannel(models.Model):
    channel_id = models.CharField(max_length=100)
    owner = models.ForeignKey(User)
    co_owner_location = models.ForeignKey(Location)

    @classmethod
    def create(cls, channel_id, owner, co_owner_location):
        return cls(channel_id=channel_id, owner=owner, co_owner_location=co_owner_location)

    def __unicode__(self):
        return "[channel_id=%s, owner=%s, co_owner_location%s]" % (self.channel_id, self.owner, self.co_owner_location)


class ChannelState(models.Model):
    channel = models.ForeignKey(MicropaymentsChannel)
    balance_timestamp = models.CharField(max_length=100)
    from_balance = models.CharField(max_length=100)
    to_balance = models.CharField(max_length=100)
    second_signature = models.CharField(max_length=150)

    @classmethod
    def create(cls, channel, balance_timestamp, from_balance, to_balance, second_signature):
        return cls(channel=channel,
                   balance_timestamp=balance_timestamp,
                   from_balance=from_balance,
                   to_balance=to_balance,
                   second_signature=second_signature)

    def __unicode__(self):
        return "[channel=%s, balance_timestamp=%s, from_balance=%s, to_balance=%s]" % \
               (self.channel, self.balance_timestamp, self.from_balance, self.to_balance)


class HashedTimelockContract(models.Model):
    channel = models.ForeignKey(MicropaymentsChannel)
    balance_timestamp = models.CharField(max_length=100)
    timeout = models.CharField(max_length=100)
    contract_hash = models.CharField(max_length=100)
    from_to_delta = models.CharField(max_length=100)
    data = models.CharField(max_length=100)
    resolved = models.BooleanField(default=False)
    second_signature = models.CharField(max_length=150)

    @classmethod
    def create(cls, channel, balance_timestamp, timeout, contract_hash, from_to_delta, data, second_signature):
        return cls(channel=channel,
                   balance_timestamp=balance_timestamp,
                   timeout=timeout,
                   contract_hash=contract_hash,
                   from_to_delta=from_to_delta,
                   data=data,
                   second_signature=second_signature)

    def __unicode__(self):
        return "[channel=%s, balance_timestamp=%s, timeout=%s, from_to_delta=%s]" % \
               (self.channel, self.balance_timestamp, self.timeout, self.from_to_delta)
