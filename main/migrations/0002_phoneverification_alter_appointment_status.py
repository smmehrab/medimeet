# Generated by Django 4.1.7 on 2023-04-11 00:54

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='PhoneVerification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', models.CharField(max_length=20)),
                ('otp', models.CharField(max_length=6)),
                ('token', models.CharField(max_length=32)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.AlterField(
            model_name='appointment',
            name='status',
            field=models.IntegerField(choices=[(1, 'Pending'), (2, 'Accepted'), (3, 'Confirmed'), (4, 'Attended'), (5, 'Unattended'), (-1, 'Rejected')], default=1),
        ),
    ]