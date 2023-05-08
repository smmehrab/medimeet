from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import RegexValidator

class PhoneVerification(models.Model):
    phone_number = models.CharField(max_length=20)
    otp = models.CharField(max_length=6)
    token = models.CharField(max_length=32)
    created_at = models.DateTimeField(default=timezone.now)

    def is_valid_token(self):
        return self.created_at > timezone.now() - timezone.timedelta(minutes=10)

# ----------------------------------------------

# class Patient(models.Model):
#     phone_number = models.CharField(max_length=20)
#     otp = models.CharField(max_length=6)
#     created_at = models.DateTimeField(default=timezone.now)
#     is_active = models.BooleanField(default=True)

#     def is_valid_token(self):
#         return self.created_at > timezone.now() - timezone.timedelta(minutes=10)

# class Admin(models.Model):
#     email = models.EmailField(_('Email Address'), unique=True)
#     username = models.CharField(_('Username'), max_length=150, unique=True)
#     fullname = models.CharField(_('Full Name'), max_length=150, blank=False)
#     phone = models.CharField(_('Phone Number'), max_length=20, blank=True)

#     address = models.TextField(_('Address'), max_length=500, blank=True)

#     date_joined = models.DateTimeField(default=timezone.now)
#     is_active = models.BooleanField(default=True)

#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['username', 'fullname', 'phone']

#     def __str__(self):
#         return self.username

# class Superadmin(models.Model):
#     email = models.EmailField(_('Email Address'), unique=True)
#     username = models.CharField(_('Username'), max_length=150, unique=True)
#     fullname = models.CharField(_('Full Name'), max_length=150, blank=False)
#     phone = models.CharField(_('Phone Number'), max_length=20, blank=True)

#     address = models.TextField(_('Address'), max_length=500, blank=True)

#     date_joined = models.DateTimeField(default=timezone.now)
#     is_staff = models.BooleanField(default=True)
#     is_active = models.BooleanField(default=True)
#     is_superuser = models.BooleanField(default=True)

#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['username', 'fullname', 'phone']

#     def __str__(self):
#         return self.username

class UserManager(BaseUserManager):

    def create_superuser(self, email, username, fullname, phone, password, **other_fields):

        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError('Superuser must be assigned to is_staff=True.')

        if other_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must be assigned to is_superuser=True.')

        return self.create_user(email, username, fullname, phone, password, **other_fields)

    def create_admin(self, email, username, password, **other_fields):
        other_fields.setdefault('is_superuser', False)
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_active', True)

        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **other_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, username, fullname, phone, password, **other_fields):

        other_fields.setdefault('is_superuser', False)
        other_fields.setdefault('is_staff', False)
        other_fields.setdefault('is_active', True)

        if not email:
            raise ValueError(_('Email address must be provided'))

        email = self.normalize_email(email)
        user = self.model(email=email, username=username, fullname=fullname, phone=phone, **other_fields)
        user.set_password(password)
        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin):

    email = models.EmailField(_('Email Address'), unique=True)
    username = models.CharField(_('Username'), max_length=150, unique=True)
    fullname = models.CharField(_('Full Name'), max_length=150, blank=False)
    phone = models.CharField(_('Phone Number'), max_length=20, blank=True)

    address = models.TextField(_('Address'), max_length=500, blank=True)

    date_joined = models.DateTimeField(default=timezone.now)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'fullname', 'phone']

    def __str__(self):
        return self.username

    # Only for Django Admin Panel
    @classmethod
    def create(cls, **kwargs):
        password = kwargs.pop('password')
        user = cls(**kwargs)
        user.set_password(password)
        user.save()
        return user

# ----------------------------------------------

class Doctor(models.Model):
    DEPARTMENT_CHOICES = [
        ('cardiology', 'Cardiology'),
        ('dentistry', 'Dentistry'),
        ('dermatology', 'Dermatology'),
        ('endocrinology', 'Endocrinology'),
        ('gastroenterology', 'Gastroenterology'),
        ('neurology', 'Neurology'),
        ('ophthalmology', 'Ophthalmology'),
        ('pediatrics', 'Pediatrics'),
    ]

    fullname = models.CharField(max_length=255)
    department = models.CharField(max_length=255, choices=DEPARTMENT_CHOICES)
    description = models.TextField(blank=True)
    image_url = models.CharField(max_length=255, blank=True)
    # image_url = models.URLField(null=True, blank=True)
    email = models.EmailField()
    # phone = models.CharField(max_length=10, validators=[RegexValidator(r'^\d{10}$')])
    phone = models.CharField(max_length=10, blank=True, validators=[])
    admin = models.ForeignKey(User, on_delete=models.SET_NULL, limit_choices_to={'is_staff': True}, null=True)

    def __str__(self):
        return self.fullname

    def clean(self):
        super().clean()

# ----------------------------------------------

class Session(models.Model):
    admin = models.ForeignKey(User, on_delete=models.SET_NULL, limit_choices_to={'is_staff': True}, null=True)
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, null=False)
    start_time = models.DateTimeField(null=False, blank=False, default=timezone.now)
    end_time = models.DateTimeField(null=False, blank=False, default=timezone.now)
    max_appointments = models.PositiveSmallIntegerField(null=False, blank=False)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def clean(self):
        super().clean()

# ----------------------------------------------

class AppointmentStatus(models.IntegerChoices):
    PENDING = 1, _('Pending')
    ACCEPTED = 2, _('Accepted')
    CONFIRMED = 3, _('Confirmed')
    ATTENDED = 4, _('Attended')
    UNATTENDED = 5, _('Unattended')
    REJECTED = -1, _('Rejected')

class Appointment(models.Model):
    session = models.ForeignKey(Session, on_delete=models.CASCADE, null=False)
    patient = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'is_staff': False}, null=False)
    appointment_type = models.CharField(max_length=255)
    appointment_note = models.TextField(null=True, blank=True)
    status = models.IntegerField(choices=AppointmentStatus.choices, default=AppointmentStatus.PENDING)

    modified_at = models.DateTimeField(null=False, blank=False, auto_now=True)

    def save(self, *args, **kwargs):
        if not self.pk:
            # Set the default status on creation
            self.status = AppointmentStatus.PENDING
        super().save(*args, **kwargs)

# ----------------------------------------------


