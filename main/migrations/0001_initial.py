# Generated by Django 4.1.7 on 2023-05-07 11:26

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='Email Address')),
                ('username', models.CharField(max_length=150, unique=True, verbose_name='Username')),
                ('fullname', models.CharField(max_length=150, verbose_name='Full Name')),
                ('phone', models.CharField(blank=True, max_length=20, verbose_name='Phone Number')),
                ('address', models.TextField(blank=True, max_length=500, verbose_name='Address')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Doctor',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fullname', models.CharField(max_length=255)),
                ('department', models.CharField(choices=[('cardiology', 'Cardiology'), ('dentistry', 'Dentistry'), ('dermatology', 'Dermatology'), ('endocrinology', 'Endocrinology'), ('gastroenterology', 'Gastroenterology'), ('neurology', 'Neurology'), ('ophthalmology', 'Ophthalmology'), ('pediatrics', 'Pediatrics')], max_length=255)),
                ('description', models.TextField(blank=True)),
                ('image_url', models.CharField(blank=True, max_length=255)),
                ('email', models.EmailField(max_length=254)),
                ('phone', models.CharField(blank=True, max_length=10)),
                ('admin', models.ForeignKey(limit_choices_to={'is_staff': True}, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
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
        migrations.CreateModel(
            name='Session',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('end_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('max_appointments', models.PositiveSmallIntegerField()),
                ('admin', models.ForeignKey(limit_choices_to={'is_staff': True}, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.doctor')),
            ],
        ),
        migrations.CreateModel(
            name='Appointment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('appointment_type', models.CharField(max_length=255)),
                ('appointment_note', models.TextField(blank=True, null=True)),
                ('status', models.IntegerField(choices=[(1, 'Pending'), (2, 'Accepted'), (3, 'Confirmed'), (4, 'Attended'), (5, 'Unattended'), (-1, 'Rejected')], default=1)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('patient', models.ForeignKey(limit_choices_to={'is_staff': False}, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.session')),
            ],
        ),
    ]
