# Generated by Django 2.2.17 on 2021-10-06 13:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('invoice', '0008_auto_20191115_2151'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='invoice',
            options={'get_latest_by': 'modified'},
        ),
    ]
