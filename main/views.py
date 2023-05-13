from django.conf import settings
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate

import random
import re

from rest_framework import generics, permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import (
    PermissionDenied, 
    ValidationError
)

from django.utils.crypto import get_random_string

from .models import (
    User,
    Doctor,
    Session,
    Appointment,
    AppointmentStatus,
    PhoneVerification,
)

from .serializers import (
    OTPVerificationTokenObtainPairSerializer,
    UserSerializer,
    UserProfileSerializer,
    DoctorSerializer,
    SessionSerializer,
    AppointmentSerializer,
    PhoneVerificationSerializer,
    DoctorProfileSerializer,
)

from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated
)

from .permissions import (
    IsSuperUser,
    IsAdmin,
    IsNotAdmin,
    IsSuperUserOrAdmin,
    IsSessionAdmin,
    IsUserSelf,
    IsDoctorSessionAdmin,
    IsDoctorAdmin,
    IsAppointmentPatientOrSessionAdmin,
    IsAppointmentSessionAdmin,
    IsAppointmentPatient
)

from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenRefreshView

class TokenGenerateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        phone = request.data.get('phone')
        password = request.data.get('password')

        if email:
            user = User.objects.filter(email=email).first()
        elif phone:
            user = User.objects.filter(phone=phone).first()
        else:
            return Response({'error': 'Please provide email or phone number.'}, status=status.HTTP_400_BAD_REQUEST)

        if user:
            authenticated_user = authenticate(username=user.username, password=password)
            print(authenticated_user)
            if authenticated_user:
                refresh = RefreshToken.for_user(authenticated_user)
                token = {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
                return Response(token, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

token_generate_view = TokenGenerateView.as_view()

class TokenVerifyView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            authorization_header = request.headers.get('Authorization')
            token = authorization_header.split('Bearer ')[1]
            AccessToken(token)
            return Response({'message': 'Token is valid.'})
        except (TokenError, IndexError):
            return Response({'error': 'Token is invalid or expired.'}, status=401)

token_verify_view = TokenVerifyView.as_view()

class TokenRefreshView(TokenRefreshView):
    pass

token_refresh_view = TokenRefreshView.as_view()

# ----------------------------------------------

class OTPSendView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PhoneVerificationSerializer

    def create(self, request, *args, **kwargs):
        phone = request.data.get('phone')

        if phone is None:
            return Response({'error': 'Invalid Phone Number'}, status=400)

        match = re.match(settings.PHONE_NUMBER_REGEX, phone)
        if match is None:
            return Response({'error': 'Invalid Phone Number'}, status=400)

        # Check if user already exists with this phone number
        user = User.objects.filter(phone=phone).first()
        if user is None:
            return Response({'error': 'User not found with this phone number'}, status=400)

        # Generate an OTP and save it to the user's session
        otp = str(random.randint(100000, 999999))
        token = get_random_string(length=32)
        verification = PhoneVerification.objects.create(
            user = user,
            phone=phone,
            otp=otp,
            token=token,
        )

        # Send the OTP to the user's phone number via a third-party SMS API
        # payload = {
        #     'api_key': settings.SMS_API_KEY,
        #     'msg': 'Your MediMeet OTP: ' + otp,
        #     'to': phone_number
        # }
        # response = requests.request("POST", settings.SMS_URL, data=payload)
        return Response({'success': True, 'token': token})

otp_send_view = OTPSendView.as_view()

class OTPVerifyView(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]
    serializer_class = OTPVerificationTokenObtainPairSerializer

otp_verify_view = OTPVerifyView.as_view()

# ----------------------------------------------

class AdminListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsSuperUser]

    def get_queryset(self):
        return User.objects.filter(is_staff=True, is_superuser=False)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        email = serializer.validated_data['email']
        username = serializer.validated_data['username']
        fullname = serializer.validated_data['fullname']
        phone = serializer.validated_data['phone']
        password = serializer.validated_data['password']
        user = User.objects.create_admin(email=email, username=username, fullname=fullname, phone=phone, password=password)
        return user

admin_list_create_view = AdminListCreateAPIView.as_view()

class AdminDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.filter(is_staff=True, is_superuser=False, is_active=True)
    lookup_field = 'id'
    name = 'Admin Details'

    def get_serializer_class(self):
        if self.request.method == "GET":
            if self.request.user.is_superuser:
                return UserSerializer
            return UserProfileSerializer
        return UserSerializer

    def get(self, request, *args, **kwargs):
        self.check_permissions(request)
        admin = self.get_object()
        serializer = self.get_serializer(admin)
        print(serializer)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        self.check_permissions(request)
        partial = kwargs.pop('partial', False)
        admin = self.get_object()
        # Check if the user making the request is the same as the admin being updated
        # or the user making the request is a superuser
        if admin.id == self.request.user.id or self.request.user.is_superuser:
            serializer = self.get_serializer(admin, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data)
        else:
            raise PermissionDenied()

    def delete(self, request, *args, **kwargs):
        self.check_permissions(request)
        admin = self.get_object()
        self.perform_destroy(admin)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.request.method == 'DELETE':
            return [IsSuperUser()]
        return [IsSuperUserOrAdmin()]

admin_detail_view = AdminDetailView.as_view()


# ----------------------------------------------

class PatientCreateView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserSerializer
    allowed_methods = ['POST']

    def create(self, request, *args, **kwargs):
        request.data['is_staff'] = False
        request.data['is_superuser'] = False
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

patient_create_view = PatientCreateView.as_view()

class PatientProfileDetailView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    lookup_field = 'id'
    name='Patient Profile'

    def get(self, request, *args, **kwargs):
        patient = self.get_object()
        serializer = self.get_serializer(patient)
        return Response(serializer.data)

    def get_permissions(self):
        return [IsUserSelf()]

patient_profile_view = PatientProfileDetailView.as_view()

class PatientAppointmentListAPIView(generics.ListAPIView):
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer

    def get_queryset(self):
        patient_id = self.kwargs['id']
        return Appointment.objects.filter(patient_id=patient_id)

    def get(self, request, *args, **kwargs):
        """
        Get a List of Appointments of a specific Patient
        """

        self.check_permissions(request)
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsUserSelf()]
        return []

patient_appointment_list_view = PatientAppointmentListAPIView.as_view()

# ----------------------------------------------

class DoctorListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = DoctorSerializer
    name = 'Get List of Doctors / Create a Doctor'

    def get_queryset(self):
        return Doctor.objects.all()

    def create(self, request, *args, **kwargs):
        self.check_permissions(request)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        doctor = serializer.save()
        headers = self.get_success_headers(serializer.data)
        return Response(self.get_serializer(doctor).data, status=status.HTTP_201_CREATED, headers=headers)

    def get_permissions(self):
        if self.request.method == 'POST':
            permission_classes = [IsSuperUser]
        else:
            permission_classes = [AllowAny]
        return [permission() for permission in permission_classes]

doctor_list_create_view = DoctorListCreateAPIView.as_view()

class DoctorRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Doctor.objects.all()
    lookup_field = 'id'
    name='Doctor Details'

    def get_serializer_class(self):
        if self.request.user.is_superuser:
            return DoctorSerializer
        else:
            return DoctorProfileSerializer

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.request.method == 'GET':
            permission_classes = [AllowAny]
        elif self.request.method == 'DELETE':
            permission_classes = [IsSuperUser]
        else:
            permission_classes = [IsSuperUser, IsAdmin]
        return [permission() for permission in permission_classes]

doctor_detail_view = DoctorRetrieveUpdateDestroyAPIView.as_view()

class DoctorAdminUpdateAPIView(generics.UpdateAPIView):
    serializer_class = DoctorSerializer
    permission_classes = [permissions.IsAdminUser]
    queryset = Doctor.objects.all()
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        doctor = self.get_object()
        admin_id = request.data.get('admin_id')

        if not admin_id:
            return Response({'admin_id': 'This field is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            admin = User.objects.get(pk=admin_id, is_staff=True)
        except User.DoesNotExist:
            return Response({'admin_id': 'Invalid Admin ID'}, status=status.HTTP_400_BAD_REQUEST)

        doctor.admin = admin
        doctor.save()
        serializer = self.get_serializer(doctor)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        doctor = self.get_object()
        doctor.admin = None
        doctor.save()
        serializer = self.get_serializer(doctor)
        return Response(serializer.data, status=status.HTTP_200_OK)

doctor_admin_update_view = DoctorAdminUpdateAPIView.as_view()

# ----------------------------------------------

class SessionListCreateAPIView(generics.ListCreateAPIView):
    queryset = Session.objects.all()
    serializer_class = SessionSerializer
    name = "Create Session / Get Session List of a Doctor"

    def get_queryset(self):
        # "__" used to access the table of the foreign key, in which, the foreign key is actually the primary key
        doctor_id = self.request.query_params.get('doctor_id')
        return Session.objects.filter(doctor__id=doctor_id, doctor__admin=self.request.user)

    def get(self, request, *args, **kwargs):
        self.check_permissions(request)
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        self.check_permissions(request)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        session = serializer.save()
        headers = self.get_success_headers(serializer.data)
        return Response(self.get_serializer(session).data, status=status.HTTP_201_CREATED, headers=headers)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsDoctorAdmin()]
        elif self.request.method == 'POST':
            return [IsDoctorAdmin()]
        return []

session_list_create_view = SessionListCreateAPIView.as_view()

class SessionDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Session.objects.all()
    serializer_class = SessionSerializer
    lookup_field = 'id'

    def get_object(self):
        id = self.kwargs['id']
        return Session.objects.filter(id=id).first()

    def get(self, request, *args, **kwargs):
        self.check_permissions(request)
        session = self.get_object()
        serializer = self.get_serializer(session)
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        self.check_permissions(request)
        session = self.get_object()
        session.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def put(self, request, *args, **kwargs):
        self.check_permissions(request)
        session = self.get_object()
        serializer = self.get_serializer(session, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_permissions(self):
        if self.request.method in ['GET', 'DELETE', 'PUT', 'PATCH']:
            return [IsDoctorSessionAdmin()]
        return []

sessions_detail_view = SessionDetailView.as_view()


# ----------------------------------------------

class AppointmentListView(generics.ListCreateAPIView):
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def get_queryset(self):
        session_id = self.kwargs['id']
        return Appointment.objects.filter(session_id=session_id)

    def get(self, request, *args, **kwargs):
        """
        Get a List of Appointments of a specific Session
        """

        self.check_permissions(request)
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Add a Appointment to a specific Session 
        """
        self.check_permissions(request)
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            if serializer.validated_data['patient'] != request.user:
                raise PermissionDenied("Invalid Patient ID")
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsSessionAdmin()]
        elif self.request.method == 'POST':
            return [IsNotAdmin(), IsAuthenticated()]
        return []

session_appointments_view = AppointmentListView.as_view()

class AppointmentView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def get_queryset(self):
        appointment_id = self.kwargs['id']
        return Appointment.objects.filter(id=appointment_id)

    def get(self, request, *args, **kwargs):
        """
        Get a specific Appointment of a specific Session 
        """

        self.check_permissions(request)
        appointment = self.get_object()

        serializer = self.get_serializer(appointment)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        """
        Modify Appointment of a specific Session 
        """

        self.check_permissions(request)
        appointment = self.get_object()

        serializer = self.get_serializer(appointment, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        """
        Delete Appointment of a specific Session 
        """

        self.check_permissions(request)
        appointment = self.get_object()
        appointment.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsAppointmentPatientOrSessionAdmin()]
        elif self.request.method == 'PUT':
            return [IsAppointmentSessionAdmin()]
        elif self.request.method == 'DELETE':
            return [IsAppointmentSessionAdmin()]
        return []

appointment_view = AppointmentView.as_view()

# ----------------------------------------------

class ConfirmCancelAppointmentView(generics.UpdateAPIView):
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def get_object(self):
        id = self.kwargs['id']
        return Appointment.objects.filter(id=id).first()

    def update(self, request, *args, **kwargs):
        self.check_permissions(request)
        instance = self.get_object()
        if 'confirm' in request.path:
            if instance.status == AppointmentStatus.ACCEPTED:
                instance.status = AppointmentStatus.CONFIRMED
            else:
                raise ValidationError('Appointment is already cancelled.')
        elif 'cancel' in request.path:
            if instance.status != AppointmentStatus.CONFIRMED:
                instance.status = AppointmentStatus.UNATTENDED
            else:
                raise ValidationError('Appointment is already confirmed.')
        instance.save()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAppointmentPatient()]
        return []

confirm_cancel_appointment_view = ConfirmCancelAppointmentView.as_view()

class AcceptRejectAppointmentView(generics.UpdateAPIView):
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        self.check_permissions(request)
        instance = self.get_object()
        if 'accept' in request.path:
            if instance.status == AppointmentStatus.PENDING:
                instance.status = AppointmentStatus.ACCEPTED
            else:
                raise ValidationError('Appointment is already handled.')
        elif 'reject' in request.path:
            if instance.status == AppointmentStatus.PENDING:
                instance.status = AppointmentStatus.REJECTED
            else:
                raise ValidationError('Appointment is already handled.')
        instance.save()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAppointmentSessionAdmin()]
        return []
    
accept_reject_appointment_view = AcceptRejectAppointmentView.as_view()
