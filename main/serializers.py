from rest_framework import serializers
from .models import User, Doctor, Session, Appointment, AppointmentStatus, PhoneVerification

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

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['fullname', 'email', 'address', 'phone']
        # read_only_fields = fields

class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = ['id', 'fullname', 'title', 'department', 'description', 'image_url', 'email', 'phone', 'admin', 'visiting_fee']
        read_only_fields = ['id', 'admin']

class DoctorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = ['fullname', 'title', 'department', 'description', 'image_url', 'visiting_fee']
        read_only_fields = fields

class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = ['id', 'admin', 'doctor', 'start_time', 'end_time', 'max_appointments', 'booked_appointments', 'confirmed_appointments', 'attended_appointments', 'modified_at']
        read_only_fields = ['id', 'booked_appointments', 'confirmed_appointments', 'attended_appointments', 'modified_at']

class AppointmentSerializer(serializers.ModelSerializer):
    status = serializers.IntegerField(read_only=True, default=AppointmentStatus.PENDING)

    class Meta:
        model = Appointment
        fields = ['id', 'doctor', 'session', 'patient', 'appointment_type', 'appointment_note', 'status', 'serial']
        read_only_fields = ['id', 'doctor', 'status', 'serial']

    def create(self, validated_data):
        session = validated_data['session']
        doctor = session.doctor
        validated_data['doctor'] = doctor
        validated_data['status'] = AppointmentStatus.PENDING
        return super().create(validated_data)

class PhoneVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneVerification
        fields = ('user', 'phone', 'otp', 'token')