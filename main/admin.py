from django.contrib import admin
from .models import User, Doctor, Session, Appointment, PhoneVerification
from django.contrib.auth.admin import UserAdmin

@admin.register(User)
class UserAdminConfig(UserAdmin):
    model = User
    
    search_fields = ('email', 'username', 'fullname', 'phone')
    list_filter = ('is_active', 'is_staff')

    ordering = ('-date_joined',)
    list_display = ('id', 'email', 'username', 'fullname', 'phone', 'address', 'is_active', 'is_staff')
    
    fieldsets = (
        (None, {'fields': ('email', 'username', 'phone',)}),
        ('Permissions', {'fields': ('is_staff', 'is_active')}),
        ('Personal', {'fields': ('fullname', 'address',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'fullname', 'phone', 'address', 'password1', 'password2', 'is_active', 'is_staff')}
         ),
    )

@admin.register(Doctor)
class DoctorAdminConfig(admin.ModelAdmin):
    list_display = ('id', 'fullname', 'department', 'description', 'email', 'image_url', 'phone', 'admin')
    list_filter = ('admin',)
    search_fields = ('fullname', 'email', 'department', 'phone')

@admin.register(Session)
class SessionAdminConfig(admin.ModelAdmin):
    list_display = ('id', 'admin', 'doctor', 'start_time', 'end_time', 'max_appointments')
    list_filter = ('admin', 'doctor')
    search_fields = ('admin__email', 'doctor__fullname')

@admin.register(Appointment)
class AppointmentAdminConfig(admin.ModelAdmin):
    list_display = ('id', 'session', 'patient', 'appointment_type', 'status', 'serial', 'modified_at')
    list_filter = ('session__doctor', 'status')
    search_fields = ('patient__email', 'appointment_type', 'appointment_note')

@admin.register(PhoneVerification)
class PhoneVerificationAdminConfig(admin.ModelAdmin):
    list_display = ['id', 'user', 'phone', 'otp', 'otp_generated_at', 'token']
    search_fields = ['phone']