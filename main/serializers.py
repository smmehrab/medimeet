from rest_framework import serializers
from .models import User, Doctor, Session, Appointment, AppointmentStatus, PhoneVerification

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('email', 'username', 'fullname', 'phone', 'password')
        read_only_fields = ['id', 'date_joined', 'is_staff', 'is_active']
        extra_kwargs = {
            'email': {'validators': []},
            # 'email': {'validators': [EmailValidator]},
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        return User.objects.create_user(**validated_data, is_active=True)

class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = ['id', 'fullname', 'image_url', 'email', 'phone', 'admin']
        read_only_fields = ['id']

class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = ['id', 'admin', 'doctor', 'start_time', 'end_time', 'max_appointments']
        read_only_fields = ['id']

class AppointmentSerializer(serializers.ModelSerializer):
    status = serializers.IntegerField(read_only=True, default=AppointmentStatus.PENDING)

    class Meta:
        model = Appointment
        fields = ['id', 'session', 'patient', 'appointment_type', 'appointment_note', 'status']
        read_only_fields = ['id', 'created_at', 'updated_at', 'status']

    def create(self, validated_data):
        validated_data['status'] = AppointmentStatus.PENDING
        return super().create(validated_data)

class PhoneVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneVerification
        fields = ('phone_number', 'otp', 'token')