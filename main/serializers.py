from rest_framework import serializers
from .models import User, Doctor, Session, Appointment, AppointmentStatus, PhoneVerification
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

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

class OTPVerificationTokenObtainPairSerializer(TokenObtainPairSerializer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.pop('email')
        self.fields.pop('password')

    def validate(self, attrs):
        phone = self.context['request'].data.get('phone')
        otp = self.context['request'].data.get('otp')
        token = self.context['request'].data.get('token')

        verification = PhoneVerification.objects.filter(
            phone=phone,
            token=token,
        ).last()

        if verification is None:
            raise serializers.ValidationError('Verification object not found')

        if not verification.is_valid_token():
            raise serializers.ValidationError('Invalid or expired token')
        if verification.otp != otp:
            raise serializers.ValidationError('Incorrect OTP')

        verification.delete()

        attrs['phone'] = phone
        return super().validate(attrs)

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['fullname', 'email', 'address', 'phone']
        # read_only_fields = fields

class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = ['id', 'fullname', 'department', 'description', 'image_url', 'email', 'phone', 'admin']
        read_only_fields = ['id']

class DoctorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = ['fullname', 'department', 'description', 'image_url']
        read_only_fields = fields

class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = ['id', 'admin', 'doctor', 'start_time', 'end_time', 'max_appointments']
        read_only_fields = ['id']

class AppointmentSerializer(serializers.ModelSerializer):
    status = serializers.IntegerField(read_only=True, default=AppointmentStatus.PENDING)

    class Meta:
        model = Appointment
        fields = ['id', 'session', 'patient', 'appointment_type', 'appointment_note', 'status', 'serial']
        read_only_fields = ['id', 'created_at', 'updated_at', 'status', 'serial']

    def create(self, validated_data):
        validated_data['status'] = AppointmentStatus.PENDING
        return super().create(validated_data)

class PhoneVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneVerification
        fields = ('user', 'phone', 'otp', 'token')