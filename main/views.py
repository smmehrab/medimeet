from django.conf import settings
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.http import HttpResponse
from django.utils import timezone

import json
from django.http import JsonResponse

import requests
import random
import re

from django.core.files.storage import FileSystemStorage
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import generics, permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import (
    PermissionDenied, 
    ValidationError
)

from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import (
    RefreshToken,
    AccessToken,
    TokenError
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenRefreshView

from django.utils.crypto import get_random_string

import os
from django.conf import settings

from .models import (
    User,
    Doctor,
    Session,
    Appointment,
    AppointmentStatus,
    PhoneVerification,
    Payment,
)

from .serializers import (
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
    DoctorSummaryPermission,
    IsAppointmentPatientOrSessionAdmin,
    IsAppointmentSessionAdmin,
    IsAppointmentPatient,
    IsPatient
)

# Token Views ------------------------------------------------------------

class TokenGenerateView(APIView):
    name = "Generate JWT Token Pair"
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
    name = "Verify JWT Token"
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
    name = "Verify JWT Token"
    pass

token_refresh_view = TokenRefreshView.as_view()

# OTP Views ------------------------------------------------------------

class OTPSendView(generics.CreateAPIView):
    name = "Send OTP"
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

        # Check if a verification object already exists for this phone number
        verification = PhoneVerification.objects.filter(phone=phone).first()

        # Generate an OTP and save it to the user's session
        otp = str(random.randint(100000, 999999))
        token = get_random_string(length=32)

        if verification is None:
            verification = PhoneVerification.objects.create(
                user=user,
                phone=phone,
                otp=otp,
                token=token,
            )
        else:
            verification.otp = otp
            verification.token = token
            verification.save()

        # Send the OTP to the user's phone number via a third-party SMS API
        payload = {
            'api_key': settings.SMS_API_KEY,
            'msg': 'Your MediMeet OTP: ' + otp,
            'to': phone
        }
        response = requests.request("POST", settings.SMS_URL, data=payload)
        return Response({'success': True, 'token': token})

otp_send_view = OTPSendView.as_view()

class OTPVerifyView(APIView):
    name = "Verify OTP and Generate JWT Token Pair"
    permission_classes = [AllowAny]

    def post(self, request):

        phone = request.data.get('phone')
        otp = request.data.get('otp')
        token = request.data.get('token')

        verification = PhoneVerification.objects.filter(
            phone=phone,
            token=token,
        ).last()

        if verification is None:
            return Response({'error': 'Invalid Credentials'}, status=400)

        if not verification.is_valid_token():
            return Response({'error': 'Invalid or Expired Token'}, status=400)

        # fetch the user object based on the phone number
        user = User.objects.filter(phone=phone).first()

        if user is None:
            return Response({'error': 'User with this phone number does not exist'}, status=400)

        if verification.otp != otp:
            return Response({'error': 'Incorrect OTP'}, status=400)

        verification.delete()

        refresh = RefreshToken.for_user(user)
        token = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        return Response(token, status=status.HTTP_200_OK)

otp_verify_view = OTPVerifyView.as_view()

# Password Views ------------------------------------------------------------

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def put(self, request):
        user = request.user
        data = request.data

        old_password = data.get('old_password')
        new_password = data.get('new_password')

        if not user.check_password(old_password):
            return Response({'error': 'Invalid old password'}, status=400)

        user.set_password(new_password)
        user.save()

        return Response({'success': 'Password changed successfully'}, status=200)

change_password_view = ChangePasswordView.as_view()

# Admin Views ------------------------------------------------------------

class AdminListCreateAPIView(generics.ListCreateAPIView):
    name = "Admin List and Create"
    serializer_class = UserSerializer
    permission_classes = [IsSuperUser]
    pagination_class = PageNumberPagination

    def get_queryset(self):
        return User.objects.filter(is_staff=True, is_superuser=False)

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        # if not queryset.exists():
        #     return Response({'error': 'No Admin Found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)

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
    name = "Admin Details"
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

# Patient Views ------------------------------------------------------------

class PatientCreateView(generics.CreateAPIView):
    name = "Patient Create"
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
    name = "Patient Profile"
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    lookup_field = 'id'

    def get(self, request, *args, **kwargs):
        patient = self.get_object()
        serializer = self.get_serializer(patient)
        return Response(serializer.data)

    def get_permissions(self):
        return [IsUserSelf()]

patient_profile_view = PatientProfileDetailView.as_view()

class PatientAppointmentListAPIView(generics.ListAPIView):
    name = "Patient Appointment List"
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    pagination_class = PageNumberPagination

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

class PatientSummaryView(APIView):
    name = "Patient Summary"

    def get(self, request, *args, **kwargs):

        try:
            patient = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            raise ValidationError('Invalid Patient ID')

        doctors = Doctor.objects.all()

        visited_doctors = 0
        summary = []
        for doctor in doctors:
            attended = Appointment.objects.filter(doctor=doctor, patient=patient, status=AppointmentStatus.ATTENDED).count()
            if attended > 0:
                visited_doctors += 1
                doctor_data = {
                    'doctor_name': doctor.fullname,
                    'appointments': {
                        'attended': attended,
                        'booked': Appointment.objects.filter(doctor=doctor, patient=patient, status=AppointmentStatus.ACCEPTED).count(),
                        'confirmed': Appointment.objects.filter(doctor=doctor, patient=patient, status=AppointmentStatus.CONFIRMED).count(),
                    }
                }
                summary.append(doctor_data)
        summary = sorted(summary, key=lambda x: x['appointments']['attended'], reverse=True)
        data = {
            'visited_doctors': visited_doctors,
            'summary': summary
        }
        return Response(data)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsAuthenticated(), IsPatient()]
        return []

patient_summary_view = PatientSummaryView.as_view()

# Doctor Views ------------------------------------------------------------

class DoctorListCreateAPIView(generics.ListCreateAPIView):
    name = "Doctor List and Create"
    pagination_class = PageNumberPagination

    def get_serializer_class(self):
        if self.request.user.is_superuser:
            return DoctorSerializer
        else:
            return DoctorProfileSerializer

    def get_queryset(self):
        return Doctor.objects.all()

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({'error': 'No Doctor Found'}, status=status.HTTP_404_NOT_FOUND)
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(queryset, many=True)
        return Response(serializer.data)

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
    name = "Doctor Details"
    queryset = Doctor.objects.all()
    lookup_field = 'id'

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

class DoctorSummaryView(APIView):
    name = "Doctor Summary"
    permission_classes = [DoctorSummaryPermission]
    lookup_field = 'id'

    def get_object(self):
        doctor_id = self.kwargs['id']
        return get_object_or_404(Doctor, id=doctor_id)

    def get(self, request, *args, **kwargs):

        try:
            doctor = self.get_object()
        except Doctor.DoesNotExist:
            raise ValidationError('Invalid Doctor ID')

        start_time = request.query_params.get('start_time')
        end_time = request.query_params.get('end_time')

        if not start_time:
            # Set default start_time to 30 days before now
            default_start_time = timezone.now() - timezone.timedelta(days=30)
            start_time = default_start_time.isoformat()
        if not end_time:
            # Set default end_time to now
            end_time = timezone.now().isoformat()

        appointments = Appointment.objects.filter(
            doctor=doctor,
            session__start_time__gte=start_time,
            session__end_time__lte=end_time
        )
        distinct_patients = appointments.values('patient').distinct()

        session_count = Session.objects.filter(
            doctor=doctor,
            start_time__gte=start_time,
            end_time__lte=end_time
        ).count()

        summary = {
            'doctor': doctor.fullname,
            'session_count': session_count,
            'patients_count': distinct_patients.count(),
            'patients': distinct_patients.values_list('patient__username', flat=True),
            'appointments': {
                'attended': appointments.filter(status=AppointmentStatus.ATTENDED).count(),
                'confirmed': appointments.filter(status=AppointmentStatus.CONFIRMED).count(),
                'booked': appointments.filter(status=AppointmentStatus.ACCEPTED).count(),
            }
        }
        return Response(summary)

doctor_summary_view = DoctorSummaryView.as_view()

# Doctor Admin Views ------------------------------------------------------------

class DoctorAdminUpdateAPIView(generics.UpdateAPIView):
    name = "Doctor Admin Update"
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

# Doctor Image Views ------------------------------------------------------------

class DoctorImageAPIView(APIView):
    name = 'Doctor Image'
    parser_classes = [MultiPartParser, FormParser]
    PATH = os.path.join(settings.MEDIA_ROOT, 'doctors')

    def get_object(self, id):
        try:
            return Doctor.objects.get(id=id)
        except Doctor.DoesNotExist:
            raise ValidationError({'doctor_id': 'Invalid Doctor ID'})

    def get(self, request, id):
        try:
            doctor = self.get_object(id=id)
        except ValidationError as e:
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)

        image = doctor.image_url

        if not image:
            return Response({'image_url': 'None'}, status=status.HTTP_404_NOT_FOUND)

        extension = image.split('.')[-1].lower()
        image_path = os.path.join(DoctorImageAPIView.PATH, image)

        # Check if the file exists before trying to open it
        if not os.path.exists(image_path):
            return Response({'image_url': '[Bad] Image Not Available'}, status=status.HTTP_404_NOT_FOUND)

        # Open the image file using the file system
        fs = FileSystemStorage(location=DoctorImageAPIView.PATH)
        image_file = fs.open(image)

        # Set the content type based on the file extension
        if extension == 'jpg' or extension == 'jpeg':
            content_type = 'image/jpeg'
        elif extension == 'png':
            content_type = 'image/png'
        else:
            content_type = 'image/*'

        # Return the image file as a response
        response = HttpResponse(image_file, content_type=content_type)
        return response

    def post(self, request, id):
        doctor = self.get_object(id)

        # Save the uploaded file to the file system using FileSystemStorage
        image_file = request.FILES['image']
        extension = image_file.name.split('.')[-1].lower()
        filename = f"{id}.{extension}"
        fs = FileSystemStorage(location=DoctorImageAPIView.PATH)
        fs.save(filename, image_file)

        # Update the doctor's image_url field
        doctor.image_url = filename
        doctor.save()

        return Response({'success': 'Image uploaded successfully', 'image_url': doctor.image_url})

    def put(self, request, id, format=None):
        doctor = self.get_object(id)

        new_image_file = request.FILES.get('image', None)
        new_image_extension = new_image_file.name.split('.')[-1].lower()

        if new_image_file is None:
            return Response({'error': 'No image file provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Delete the old image
        old_image = doctor.image_url
        if old_image:
            old_image_path = os.path.join(DoctorImageAPIView.PATH, old_image)
            if os.path.exists(old_image_path):
                fs = FileSystemStorage(location=DoctorImageAPIView.PATH)
                fs.delete(old_image)

        # Save the uploaded file to the file system using FileSystemStorage
        filename = f"{id}.{new_image_extension}"
        fs = FileSystemStorage(location=DoctorImageAPIView.PATH)
        fs.save(filename, new_image_file)

        # Update the doctor's image_url field
        doctor.image_url = filename
        doctor.save()

        return Response({'success': 'Image updated successfully', 'image_url': doctor.image_url})

    def delete(self, request, id, format=None):
        doctor = self.get_object(id)

        image = doctor.image_url

        # Update the doctor's image_url field
        doctor.image_url = None
        doctor.save()

        # Delete the image file from the file system using FileSystemStorage
        if image is not None:
            fs = FileSystemStorage(location=DoctorImageAPIView.PATH)
            try:
                fs.delete(image)
            except FileNotFoundError:
                return Response({'image_url': 'Image Not Found'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'success': 'Image deleted successfully', 'image_url': doctor.image_url})

    def get_permissions(self):
        if self.request.method == 'GET':
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsSuperUser]
        return [permission() for permission in permission_classes]

doctor_image_view = DoctorImageAPIView.as_view()

# Session Views ------------------------------------------------------------

class SessionListCreateAPIView(generics.ListCreateAPIView):
    name = "Session List and Create"
    queryset = Session.objects.all()
    serializer_class = SessionSerializer
    pagination_class = PageNumberPagination

    def get_queryset(self):

        doctor_id = self.request.query_params.get('doctor_id')

        if doctor_id is None:
            return Response({'error': f'No doctor_id Provided'}, status=status.HTTP_404_NOT_FOUND)

        try:
            doctor = Doctor.objects.get(id=doctor_id)
        except Doctor.DoesNotExist:
            return Response({'error': f'No Doctor Found with doctor_id=={doctor_id}'}, status=status.HTTP_404_NOT_FOUND)

        # queryset = Session.objects.filter(doctor__id=doctor_id)
        queryset = Session.objects.filter(doctor=doctor)

        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')

        if start_date and end_date:
            queryset = queryset.filter(start_time__gte=start_date, start_time__lte=end_date)
            queryset = queryset.order_by('start_time')
        elif start_date:
            queryset = queryset.filter(start_time__gte=start_date)
            queryset = queryset.order_by('start_time')
        elif end_date:
            queryset = queryset.filter(start_time__lte=end_date)
            queryset = queryset.order_by('-end_time')
        else:
            queryset = queryset.filter(start_time__gte=timezone.now())
            queryset = queryset.order_by('start_time')

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def get(self, request, *args, **kwargs):
        self.check_permissions(request)
        return self.get_queryset()

    def create(self, request, *args, **kwargs):
        self.check_permissions(request)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        session = serializer.save()
        headers = self.get_success_headers(serializer.data)
        return Response(self.get_serializer(session).data, status=status.HTTP_201_CREATED, headers=headers)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        elif self.request.method == 'POST':
            return [IsDoctorAdmin()]
        return []

session_list_create_view = SessionListCreateAPIView.as_view()

class SessionDetailView(generics.RetrieveUpdateDestroyAPIView):
    name = "Session Detail"
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
        if self.request.method == 'GET':
            return [AllowAny()]
        if self.request.method in ['DELETE', 'PUT', 'PATCH']:
            return [IsDoctorSessionAdmin()]
        return []

sessions_detail_view = SessionDetailView.as_view()

# Appointment Views ------------------------------------------------------------

class AppointmentListCreateView(generics.ListCreateAPIView):
    name = "Appointment List and Create"
    serializer_class = AppointmentSerializer
    lookup_field = 'id'
    pagination_class = PageNumberPagination

    def get_queryset(self):
        session_id = self.kwargs['id']
        return Appointment.objects.filter(session_id=session_id)

    def get(self, request, *args, **kwargs):
        """
            Get a List of Appointments of a specific Session
        """

        self.check_permissions(request)
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({'error': 'No Appointment Found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
            Add a Appointment to a specific Session 
        """
        self.check_permissions(request)

        try:
            session = Session.objects.get(pk=self.kwargs['id'])
        except Session.DoesNotExist:
            return Response({'error': 'Invalid Session ID'}, status=status.HTTP_400_BAD_REQUEST)

        existing_appointment = Appointment.objects.filter(session=session, patient=request.user)
        if existing_appointment.exists():
            return Response({'error': 'You already have an appointment for this session.'}, status=status.HTTP_400_BAD_REQUEST)

        request.data['session'] = session.id
        request.data['patient'] = request.user.id

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            if (session.booked_appointments + session.confirmed_appointments) >= session.max_appointments:
                raise ValidationError('Session is fully booked. Please try another session.')
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsSessionAdmin()]
        elif self.request.method == 'POST':
            return [IsNotAdmin(), IsAuthenticated()]
        return []

appointment_list_create_view = AppointmentListCreateView.as_view()

class AppointmentView(generics.RetrieveUpdateDestroyAPIView):
    name = "Appointment Details"
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def get(self, request, *args, **kwargs):
        self.check_permissions(request)
        appointment = self.get_object()
        serializer = self.get_serializer(appointment)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        self.check_permissions(request)
        appointment = self.get_object()
        serializer = self.get_serializer(appointment, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
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

# Appointment Status Views ------------------------------------------------------------

class ConfirmAppointmentView(generics.UpdateAPIView):
    name = "Confirm Appointment"
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        self.check_permissions(request)

        appointment = self.get_object()
        
        if appointment.status == AppointmentStatus.ACCEPTED:

            payment_id = request.data['payment_id']

            if not payment_id:
                raise ValidationError('Payment ID is required to Confirm Appointment')

            # Actual API call to bKash API
            url = 'https://checkout.sandbox.bka.sh/v1.2.0-beta/checkout/payment/query/' + str(payment_id)
            # response = requests.get(url)

            # Dummy API call to bKash API
            data = {
                "paymentID": payment_id,
                "createTime": "string",
                "updateTime": "string",
                "trxID": "string",
                "transactionStatus": "string",
                "amount": 100,
                "currency": "string",
                "intent": "string",
                "merchantInvoiceNumber": "string",
                "refundAmount": "string"
            }
            # Create a JSON response with the data and status code 200
            response = JsonResponse(data, status=200)

            if response.status_code == 200:
                # api_data = response.data
                api_data = json.loads(response.content)
                # Create a Payment instance with the API response data
                payment = Payment(
                    payment_id=api_data['paymentID'],
                    create_time=api_data['createTime'],
                    update_time=api_data['updateTime'],
                    trx_id=api_data['trxID'],
                    transaction_status=api_data['transactionStatus'],
                    amount=api_data['amount'],
                    currency=api_data['currency'],
                    intent=api_data['intent'],
                    merchant_invoice_number=api_data['merchantInvoiceNumber'],
                    refund_amount=api_data['refundAmount'],
                    appointment=appointment
                )
                # Save the Payment instance to the database
                payment.save()

                if payment.amount != 100:
                    raise ValidationError('Invalid Payment Amount')

                # Confirm appointment
                appointment.status = AppointmentStatus.CONFIRMED
                # Increment the confirmed_appointments count of the session
                session_confirmed_appointments =  appointment.session.confirmed_appointments
                appointment.session.confirmed_appointments = session_confirmed_appointments + 1
                appointment.session.save()
            else:
                return HttpResponse('API call failed')

        else:
            raise ValidationError('Appointment is not in ACCEPTED status.')
        
        appointment.save()
        serializer = self.get_serializer(appointment)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAppointmentPatient()]
        return []

confirm_appointment_view = ConfirmAppointmentView.as_view()

class CancelAppointmentView(generics.UpdateAPIView):
    name = "Cancel Appointment"
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        self.check_permissions(request)

        appointment = self.get_object()
        if appointment.status != AppointmentStatus.CONFIRMED:
            appointment.status = AppointmentStatus.UNATTENDED
        else:
            raise ValidationError('Appointment is already in CONFIRMED status')

        appointment.save()
        serializer = self.get_serializer(appointment)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAppointmentPatient()]
        return []

cancel_appointment_view = CancelAppointmentView.as_view()

class AcceptAppointmentView(generics.UpdateAPIView):
    name = "Accept Appointment"
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        self.check_permissions(request)

        appointment = self.get_object()
        if appointment.status == AppointmentStatus.PENDING:
            appointment.status = AppointmentStatus.ACCEPTED
            # Increment the booked_appointments count of the session
            session_booked_appointments =  appointment.session.booked_appointments
            appointment.session.booked_appointments = session_booked_appointments + 1
            appointment.session.save()
            # send email to patient
            # send_mail(
            #     'Appointment Booked',
            #     'Your appointment has been booked. Serial Number would be decided upon arrival.',
            #     'from@example.com', 
            #     [instance.patient.email],
            #     fail_silently=False,
            # )
        else:
            raise ValidationError('Appointment is not in PENDING status.')

        appointment.save()
        serializer = self.get_serializer(appointment)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAppointmentSessionAdmin()]
        return []

accept_appointment_view = AcceptAppointmentView.as_view()

class RejectAppointmentView(generics.UpdateAPIView):
    name = "Reject Appointment"
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        self.check_permissions(request)

        appointment = self.get_object()
        if appointment.status == AppointmentStatus.PENDING:
            appointment.status = AppointmentStatus.REJECTED
        else:
            raise ValidationError('Appointment is not in PENDING status.')

        appointment.save()
        serializer = self.get_serializer(appointment)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAppointmentSessionAdmin()]
        return []

reject_appointment_view = RejectAppointmentView.as_view()

class AttendAppointmentView(generics.UpdateAPIView):
    name = "Attend Appointment"
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        self.check_permissions(request)

        appointment = self.get_object()

        session_start_time = appointment.session.start_time
        current_time = timezone.now()
        if current_time < session_start_time:
            raise ValidationError('Session has not started yet.')

        if appointment.status == AppointmentStatus.ACCEPTED or appointment.status == AppointmentStatus.CONFIRMED:
            appointment.status = AppointmentStatus.ATTENDED
            # Increment the attended_appointments count of the session
            session_attended_appointments =  appointment.session.attended_appointments
            appointment.session.attended_appointments = session_attended_appointments + 1
            appointment.session.save()
        else:
            raise ValidationError('Invalid Appointment to Attend')

        appointment.save()
        serializer = self.get_serializer(appointment)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAppointmentSessionAdmin()]
        return []

attend_appointment_view = AttendAppointmentView.as_view()

class UnattendAppointmentView(generics.UpdateAPIView):
    name = "Unattend Appointment"
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        self.check_permissions(request)

        appointment = self.get_object()

        session_start_time = appointment.session.start_time
        current_time = timezone.now()
        if current_time < session_start_time:
            raise ValidationError('Session has not started yet.')

        if appointment.status == AppointmentStatus.ACCEPTED or appointment.status == AppointmentStatus.CONFIRMED:
            appointment.status = AppointmentStatus.UNATTENDED
        else:
            raise ValidationError('Invalid Appointment to Unattend')

        appointment.save()
        serializer = self.get_serializer(appointment)
        return Response(serializer.data)

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAppointmentSessionAdmin()]
        return []

unattend_appointment_view = UnattendAppointmentView.as_view()

# END ------------------------------------------------------------
