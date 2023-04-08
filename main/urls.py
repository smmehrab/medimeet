from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name = 'home'),

    path('doctors', views.doctors_create_view),
    path('sessions', views.sessions_create_view),
    path('appointments', views.appointments_create_view),
    # path('', views.home, name = 'home'),
    # path('', views.home, name = 'home'),
    # path('', views.home, name = 'home'),
    # path('', views.home, name = 'home'),
    # path('', views.home, name = 'home'),

]