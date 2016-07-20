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

    def get_hostname(self):
        return self.hostname

    def get_port(self):
        return self.port


class MicropaymentsChannel(models.Model):
    channel_id = models.CharField(max_length=100)
    owner = models.ForeignKey(User)
    co_owner_location = models.ForeignKey(Location)

    @classmethod
    def create(cls, channel_id, owner, co_owner_location):
        return cls(channel_id=channel_id, owner=owner, co_owner_location=co_owner_location)

    @classmethod
    def get(cls, cid, owner):
        return cls.objects.get(channel_id=cid, owner=owner)

    def __unicode__(self):
        return "[channel_id=%s, owner=%s, co_owner_location%s]" % (self.channel_id, self.owner, self.co_owner_location)

    def get_cid(self):
        return int(self.channel_id)

    def get_owner(self):
        return self.owner

    def get_owner_address(self):
        return self.owner.useraddress.address

    def get_co_owner_location(self):
        return self.co_owner_location


class ChannelState(models.Model):
    channel = models.ForeignKey(MicropaymentsChannel)
    balance_timestamp = models.CharField(max_length=100)
    from_balance = models.CharField(max_length=100)
    to_balance = models.CharField(max_length=100)
    signature = models.CharField(max_length=150)
    second_signature = models.CharField(max_length=150)

    @classmethod
    def create(cls, micropayments_channel, balance_timestamp, from_balance, to_balance, signature, second_signature):
        return cls(channel=micropayments_channel,
                   balance_timestamp=balance_timestamp,
                   from_balance=from_balance,
                   to_balance=to_balance,
                   signature=signature,
                   second_signature=second_signature)

    @classmethod
    def delete_old(cls, micropayments_channel, balance_timestamp):
        cls.objects.filter(channel=micropayments_channel).exclude(balance_timestamp=balance_timestamp).delete()

    def __unicode__(self):
        return "[channel=%s, balance_timestamp=%s, from_balance=%s, to_balance=%s]" % \
               (self.channel, self.balance_timestamp, self.from_balance, self.to_balance)

    def get_channel(self):
        return self.channel

    def get_balance_timestamp(self):
        return int(self.balance_timestamp)

    def get_from_balance(self):
        return int(self.from_balance)

    def get_to_balance(self):
        return int(self.to_balance)

    def get_signature(self):
        return self.signature

    def get_second_signature(self):
        return self.second_signature

    def to_request_dict(self):
        return {
            "balance_timestamp": self.get_balance_timestamp(),
            "from_balance": self.get_from_balance(),
            "to_balance": self.get_to_balance(),
            "signature": self.get_signature()
        }


class HashedTimelockContract(models.Model):
    channel = models.ForeignKey(MicropaymentsChannel)
    balance_timestamp = models.CharField(max_length=100)
    timeout = models.CharField(max_length=100)
    contract_hash = models.CharField(max_length=100)
    from_to_delta = models.CharField(max_length=100)
    data = models.CharField(max_length=100)
    resolved = models.BooleanField(default=False)
    signature = models.CharField(max_length=150)

    @classmethod
    def create(cls,
               micropayments_channel,
               balance_timestamp,
               timeout,
               contract_hash,
               from_to_delta,
               data,
               signature):
        return cls(channel=micropayments_channel,
                   balance_timestamp=balance_timestamp,
                   timeout=timeout,
                   contract_hash=contract_hash,
                   from_to_delta=from_to_delta,
                   data=data,
                   signature=signature)

    def __unicode__(self):
        return "[channel=%s, balance_timestamp=%s, timeout=%s, from_to_delta=%s]" % \
               (self.channel, self.balance_timestamp, self.timeout, self.from_to_delta)

    def get_channel(self):
        return self.channel

    def get_cid(self):
        return self.channel.get_cid()

    def get_owner(self):
        return self.channel.get_owner()

    def get_owner_address(self):
        return self.channel.get_owner_address()

    def get_balance_timestamp(self):
        return int(self.balance_timestamp)

    def get_timeout(self):
        return int(self.timeout)

    def get_hash(self):
        return self.contract_hash

    def get_from_to_delta(self):
        return int(self.from_to_delta)

    def get_data(self):
        return self.data

    def get_resolved(self):
        return self.resolved

    def get_signature(self):
        return self.signature

    def to_request_dict(self):
        return {
            "balance_timestamp": self.get_balance_timestamp(),
            "timeout": self.get_timeout(),
            "hash": self.get_hash(),
            "from_to_delta": self.get_from_to_delta(),
            "signature": self.get_signature()
        }
