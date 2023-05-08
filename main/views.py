from django.conf import settings
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt

import coreapi
import requests
import random
import re

from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from .models import Doctor, Session, Appointment, AppointmentStatus, PhoneVerification
from .serializers import UserSerializer, DoctorSerializer, SessionSerializer, AppointmentSerializer, PhoneVerificationSerializer, DoctorProfileSerializer

from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated

from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from rest_framework.exceptions import PermissionDenied, ValidationError
from .permissions import IsSuperUserOrReadOnly, IsNotAdmin, IsSessionAdmin, IsUserSelf, IsDoctorSessionAdmin, IsDoctorAdmin, IsAppointmentPatientOrSessionAdmin, IsAppointmentSessionAdmin, IsAppointmentPatient
from django.utils.crypto import get_random_string

from datetime import datetime, timedelta
import jwt

# ----------------------------------------------

class OTPSendView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PhoneVerificationSerializer

    def create(self, request, *args, **kwargs):
        phone_number = request.data.get('phone_number')

        if phone_number is None:
            return Response({'error': 'Invalid Phone Number'}, status=400)

        match = re.match(settings.PHONE_NUMBER_REGEX, phone_number)
        if match is None:
            return Response({'error': 'Invalid Phone Number'}, status=400)

        # Generate an OTP and save it to the user's session
        otp = str(random.randint(100000, 999999))
        request.session['phone_number'] = phone_number
        request.session['otp'] = otp

        token = get_random_string(length=32)
        verification = PhoneVerification.objects.create(
            phone_number=phone_number,
            otp=otp,
            token=token,
        )

        # Send the OTP to the user's phone number via a third-party SMS API
        payload = {
            'api_key': settings.SMS_API_KEY,
            'msg': 'Your MediMeet OTP: ' + otp,
            'to': phone_number
        }
        response = requests.request("POST", settings.SMS_URL, data=payload)
        return Response({'success': True, 'token': token})

otp_send_view = OTPSendView.as_view()

class OTPVerifyView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PhoneVerificationSerializer

    def create(self, request, *args, **kwargs):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')
        token = request.data.get('token')
        verification = PhoneVerification.objects.filter(
            phone_number=phone_number,
            token=token,
        ).last()

        if verification is None:
            return Response({'error': 'Verification object not found'}, status=status.HTTP_400_BAD_REQUEST)

        if not verification.is_valid_token():
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)
        if verification.otp != otp:
            return Response({'error': 'Incorrect OTP'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a JWT token using the user's phone number and a secret key
        expiration_time = datetime.utcnow() + timedelta(days=1)
        payload = {
            'phone_number': phone_number,
            'exp': expiration_time
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        return Response({'success': True, 'token': token})

otp_verify_view = OTPVerifyView.as_view()

# @csrf_exempt
# @api_view(['POST'])
# @permission_classes([AllowAny])
# def otp_send(request):
#     phone_number = request.data.get('phone_number')

#     if phone_number is None:
#         return Response({'error': 'Invalid Phone Number'}, status=400)

#     match = re.match(settings.PHONE_NUMBER_REGEX, phone_number)
#     if match is None:
#         return Response({'error': 'Invalid Phone Number'}, status=400)

#     # Generate an OTP and save it to the user's session
#     otp = str(random.randint(100000, 999999))
#     request.session['phone_number'] = phone_number
#     request.session['otp'] = otp

#     token = get_random_string(length=32)
#     verification = PhoneVerification.objects.create(
#         phone_number=phone_number,
#         otp=otp,
#         token=token,
#     )

#     # Send the OTP to the user's phone number via a third-party SMS API
#     payload = {
#         'api_key': settings.SMS_API_KEY,
#         'msg': 'Your MediMeet OTP: ' + otp,
#         'to': phone_number
#     }
#     response = requests.request("POST", settings.SMS_URL, data=payload)
#     return Response({'success': True, 'token': token})

# @api_view(['POST'])
# @permission_classes([AllowAny])
# def otp_verify(request):
#     phone_number = request.data.get('phone_number')
#     otp = request.data.get('otp')
#     token = request.data.get('token')
#     verification = get_object_or_404(
#         PhoneVerification,
#         phone_number=phone_number,
#         token=token,
#     )
#     if not verification.is_valid_token():
#         return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)
#     if verification.otp != otp:
#         return Response({'error': 'Incorrect OTP'}, status=status.HTTP_400_BAD_REQUEST)

#     # Generate a JWT token using the user's phone number and a secret key
#     from datetime import datetime, timedelta
#     import jwt
#     expiration_time = datetime.utcnow() + timedelta(days=1)
#     payload = {
#         'phone_number': phone_number,
#         'exp': expiration_time
#     }
#     token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
#     return Response({'success': True, 'token': token})

# ----------------------------------------------

class AdminSignInView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer
    permission_classes = [AllowAny]

admin_signin_view = AdminSignInView.as_view()

# ----------------------------------------------

class PatientCreateView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        request.data['is_staff'] = False
        request.data['is_superuser'] = False
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

patient_signup_view = PatientCreateView.as_view()

class PatientSignInView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer
    permission_classes = [IsNotAdmin]

patient_signin_view = PatientSignInView.as_view()


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
    name = 'List of Doctors'

    def get_queryset(self):
        return Doctor.objects.all()

    def get_permissions(self):
        if self.request.method == 'POST':
            permission_classes = [IsSuperUserOrReadOnly]
        else:
            permission_classes = [permissions.AllowAny]
        return [permission() for permission in permission_classes]

doctor_list_create_view = DoctorListCreateAPIView.as_view()

class DoctorProfileDetailView(generics.RetrieveAPIView):
    queryset = Doctor.objects.all()
    serializer_class = DoctorProfileSerializer
    lookup_field = 'id'
    name='Doctor Profile Info'

    def get_object(self):
        id = self.kwargs['id']
        return Doctor.objects.filter(id=id).first()

    def get(self, request, *args, **kwargs):
        doctor = self.get_object()
        serializer = self.get_serializer(doctor)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return []

doctor_profile_view = DoctorProfileDetailView.as_view()

# ----------------------------------------------

class SessionListCreateAPIView(generics.ListCreateAPIView):
    queryset = Session.objects.all()
    serializer_class = SessionSerializer

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

sessions_create_view = SessionListCreateAPIView.as_view()

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
