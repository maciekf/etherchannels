# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-06-24 18:45
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='MicropaymentsChannel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('channel_id', models.CharField(max_length=70)),
                ('channel_address', models.CharField(max_length=70)),
                ('from_address', models.CharField(max_length=70)),
                ('from_balance', models.CharField(max_length=70)),
                ('to_address', models.CharField(max_length=70)),
                ('to_balance', models.CharField(max_length=70)),
                ('balance_timestamp', models.CharField(max_length=70)),
                ('balance_signature', models.CharField(max_length=140)),
            ],
        ),
    ]
