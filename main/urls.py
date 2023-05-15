from django.urls import path, re_path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from . import views

schema_view = get_schema_view(
   openapi.Info(
      title="MediMeet API",
      default_version='v1.2',
      description="Doctor Appointment Scheduling App",
      terms_of_service="",
      contact=openapi.Contact(email="smmehrabul-2017614964@cs.du.ac.bd"),
      license=openapi.License(name="Apache License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),

    # Auth
    path('auth/', include([
        path('signin', views.token_generate_view, name='signin'),
        path('otp/send', views.otp_send_view, name='otp_send'),
        path('otp/verify', views.otp_verify_view, name='otp_verify'),
        path('password/change', views.change_password_view, name='change_password'),
        path('token', views.token_generate_view, name='token_generate'),
        path('token/verify', views.token_verify_view, name='token_verify'),
        path('token/refresh', views.token_refresh_view, name='token_refresh'),
    ])),

    # Patient
    path('patient', views.patient_create_view, name="patient_create"),
    path('patient/', include([
        path('<int:id>', views.patient_profile_view, name="patient_detail"),
        path('<int:id>/appointments', views.patient_appointment_list_view, name="patient_appointments"),
    ])),

    # Admin
    path('admin', views.admin_list_create_view, name='admin_list_create'),
    path('admin/<int:id>', views.admin_detail_view, name='admin_detail'),

    # Doctor
    path('doctor', views.doctor_list_create_view, name='doctor_list_create'),
    path('doctor/', include([
        path('<int:id>', views.doctor_detail_view, name='doctor_detail'),
        path('<int:id>/admin', views.doctor_admin_update_view, name='doctor_admin_update'),
        path('<int:id>/image', views.doctor_image_view, name='doctor_image'),
    ])),

    # Session
    path('session', views.session_list_create_view, name='session_list_create'),
    path('session/', include([
        path('<int:id>', views.sessions_detail_view, name='sessions_detail'),
        path('<int:id>/appointments', views.appointment_list_create_view, name='appointment_list_create'),
    ])),

    # Appointment
    path('appointment/', include([
        path('<int:id>', views.appointment_view, name='appointment_detail'),
        path('<int:id>/confirm', views.confirm_appointment_view, name='confirm_appointment'),
        path('<int:id>/cancel', views.cancel_appointment_view, name='cancel_appointment'),
        path('<int:id>/accept', views.accept_appointment_view, name='accept_appointment'),
        path('<int:id>/reject', views.reject_appointment_view, name='reject_appointment'),
        path('<int:id>/attend', views.attend_appointment_view, name='attend_appointment'),
        path('<int:id>/unattend', views.unattend_appointment_view, name='unattend_appointment'),
    ])),

    re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]

# urlpatterns = [
#     path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),

#     path('auth/signin', views.token_generate_view, name='signin'),
#     path('auth/otp/send', views.otp_send_view, name='otp_send'),
#     path('auth/otp/verify', views.otp_verify_view, name='otp_verify'),

#     path('auth/token', views.token_generate_view, name='token_generate'),
#     path('auth/token/verify', views.token_verify_view, name='token_verify'),
#     path('auth/token/refresh', views.token_refresh_view, name='token_refresh'),
#     # path('auth/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
#     # path('auth/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
#     # path('auth/token/verify', TokenVerifyView.as_view(), name='token_verify'),

#     path('patient', views.patient_create_view),
#     path('patient/<int:id>', views.patient_profile_view, name="patient_detail"),
#     path('patient/<int:id>/appointments', views.patient_appointment_list_view, name="patient_appointments"),

#     path('admin', views.admin_list_create_view, name='admin_list_create'),
#     path('admin/<int:id>', views.admin_detail_view, name='admin_detail'),

#     path('doctor', views.doctor_list_create_view, name = 'doctor_list_create'),
#     path('doctor/<int:id>', views.doctor_detail_view, name='doctor_detail'),
#     path('doctor/<int:id>/admin', views.doctor_admin_update_view, name='doctor_admin_update'),
#     path('doctor/<int:id>/image', views.doctor_image_view, name='doctor_image'),

#     # path('doctor/<int:id>/patient', views.doctor_patient_list_view, name='doctor_patient_list'),
#     # path('doctor/<int:id>/patient/<int:pid>', views.doctor_patient_appointment_list_view, name='doctor_patient_appointment_list'),

#     path('session', views.session_list_create_view, name='session_list_create'),
#     path('session/<int:id>', views.sessions_detail_view, name='sessions_detail'),
#     path('session/<int:id>/appointments', views.appointment_list_create_view, name='appointment_list_create'),

#     path('appointment/<int:id>', views.appointment_view, name='appointment_detail'),
#     path('appointment/<int:id>/confirm', views.confirm_appointment_view, name='confirm_appointment'),
#     path('appointment/<int:id>/cancel', views.cancel_appointment_view, name='cancel_appointment'),
#     path('appointment/<int:id>/accept', views.accept_appointment_view, name='accept_appointment'),
#     path('appointment/<int:id>/reject', views.reject_appointment_view, name='reject_appointment'),
#     path('appointment/<int:id>/attend', views.attend_appointment_view, name='attend_appointment'),
#     path('appointment/<int:id>/unattend', views.unattend_appointment_view, name='unattend_appointment'),

#     re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
#     re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
#     re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
# ]