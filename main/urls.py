from django.urls import path, re_path
from . import views

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
   openapi.Info(
      title="MediMeet API",
      default_version='v1.1',
      description="Doctor Appointment Scheduling App",
      terms_of_service="",
      contact=openapi.Contact(email="mehrab.24csedu.001@gmail.com"),
      license=openapi.License(name="Apache License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),

    path('token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify', TokenVerifyView.as_view(), name='token_verify'),

    path('patient/signup', views.patient_signup_view),
    path('patient/signin', views.patient_signin_view),

    path('patient/<int:id>/appointments', views.patient_appointment_list_view),

    path('admin/signin', views.admin_signin_view),

    path('doctors', views.doctors_create_view),

    path('session', views.sessions_create_view),
    path('session/<int:id>', views.sessions_detail_view, name='get, update or delete session detail'),
    path('session/<int:id>/appointments', views.session_appointments_view, name='add to or get from the appointments list of a session'),

    path('appointment/<int:id>', views.appointment_view, name='get an appointment details'),
    
    path('appointment/<int:id>/confirm', views.confirm_cancel_appointment_view, name='confirm an appointment'),
    path('appointment/<int:id>/cancel', views.confirm_cancel_appointment_view, name='cancel an appointment'),

    path('appointment/<int:id>/accept', views.accept_reject_appointment_view, name='accept an appointment'),
    path('appointment/<int:id>/reject', views.accept_reject_appointment_view, name='reject an appointment'),

    path('otp/send', views.otp_send, name='send otp'),
    path('otp/verify', views.otp_verify, name='verify otp'),

    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]