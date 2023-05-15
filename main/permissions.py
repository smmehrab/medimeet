from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import Doctor, Session, Appointment
from django.shortcuts import get_object_or_404

# class CustomPermission(permissions.DjangoModelPermissions):
#     perms_map = {
#         'GET': ['%(app_label)s.view_%(model_name)s'],
#         'OPTIONS': [],
#         'HEAD': [],
#         'POST': ['%(app_label)s.add_%(model_name)s'],
#         'PUT': ['%(app_label)s.change_%(model_name)s'],
#         'PATCH': ['%(app_label)s.change_%(model_name)s'],
#         'DELETE': ['%(app_label)s.delete_%(model_name)s'],
# }

#-------------------------------------------------------------------

class IsUserSelf(BasePermission):
    """
    Allows access only to the authenticated user whose ID is specified in the URL.
    """
    def has_permission(self, request, view):
        user_id = view.kwargs.get('id')
        return request.user.is_authenticated and request.user.id == user_id

class IsAppointmentSessionAdmin(BasePermission):
    def has_permission(self, request, view):
        appointment_id = view.kwargs.get('id')
        appointment = get_object_or_404(Appointment, id=appointment_id)
        session = Session.objects.filter(id=appointment.session.id, admin=request.user).first()
        return session is not None

class IsAppointmentPatientOrSessionAdmin(BasePermission):
    def has_permission(self, request, view):
        appointment_id = view.kwargs.get('id')
        appointment = Appointment.objects.filter(id=appointment_id, patient=request.user).first()

        if appointment is not None:
            return True

        appointment = Appointment.objects.filter(id=appointment_id).first()
        session = Session.objects.filter(id=appointment.session.id, admin=request.user).first()
        return (session is not None)

class IsDoctorAdmin(BasePermission):
    def has_permission(self, request, view):
        doctor_id = request.query_params.get('doctor_id')
        if doctor_id is None:
            doctor_id = request.data['doctor']
            admin_id = request.data['admin']

            if request.user.id != admin_id:
                return False

        doctor = Doctor.objects.filter(id=doctor_id, admin=request.user).first()
        return doctor is not None

class IsDoctorSessionAdmin(BasePermission):
    def has_permission(self, request, view):
        # Check if user is admin of doctor in the session being accessed
        session_id = view.kwargs.get('id')
        session = Session.objects.filter(id=session_id, doctor__admin=request.user).first()
        return session is not None

class IsAppointmentPatient(BasePermission):
    def has_permission(self, request, view):
        appointment_id = view.kwargs.get('id')
        appointment = Appointment.objects.filter(id=appointment_id, patient=request.user).first()
        return appointment is not None

class IsSessionAdmin(BasePermission):
    def has_permission(self, request, view):
        session_id = view.kwargs.get('id')
        session = Session.objects.filter(id=session_id, admin=request.user).first()
        return session is not None

class IsPatient(BasePermission):
    def has_permission(self, request, view):
        return not request.user.is_superuser and not request.user.is_staff and request.user.is_active

class IsNotPatient(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_superuser or request.user.is_staff or not request.user.is_active

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_staff

class IsNotAdmin(BasePermission):
    def has_permission(self, request, view):
        return not request.user.is_staff

class IsSuperUserOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return request.user.is_superuser

class IsSuperUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_superuser

class IsSuperUserOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_superuser or request.user.is_staff

#-------------------------------------------------------------------

class IsDoctorUserOrReadOnly(BasePermission):
    """
    Custom permission to only allow doctor users to edit an object,
    and allow all users to view it.
    """
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return request.user.is_authenticated and request.user.is_doctor


class IsPatientUserOrReadOnly(BasePermission):
    """
    Custom permission to only allow patient users to edit an object,
    and allow all users to view it.
    """
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return request.user.is_authenticated and not request.user.is_doctor


class IsAdminUser(BasePermission):
    """
    Custom permission to only allow admin users.
    """
    def has_permission(self, request, view):
        return request.user.is_superuser


class IsDoctorUser(BasePermission):
    """
    Custom permission to only allow doctor users.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_doctor


class IsPatientUser(BasePermission):
    """
    Custom permission to only allow patient users.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and not request.user.is_doctor


class IsAppointmentOwnerOrAdminUser(BasePermission):
    """
    Custom permission to only allow appointment owner or admin users to edit/delete an object.
    """
    def has_object_permission(self, request, view, obj):
        return obj.patient == request.user or request.user.is_superuser
