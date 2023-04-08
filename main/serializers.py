from rest_framework import serializers
from .models import User, Doctor, Session, Appointment

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'fullname', 'phone', 'address', 'date_joined', 'is_staff', 'is_active']
        read_only_fields = ['id', 'date_joined', 'is_staff', 'is_active']
        extra_kwargs = {
            'email': {'validators': []},
            'password': {'write_only': True},
        }

class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = ['id', 'fullname', 'image_url', 'email', 'phone', 'admin']

class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = ['id', 'admin', 'doctor', 'start_time', 'end_time', 'max_appointments']

class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = ['id', 'session', 'patient', 'appointment_type', 'appointment_note', 'status']


# from . import validators

# class ProductSerializer(serializers.ModelSerializer):
#     owner = UserPublicSerializer(source='user', read_only=True)
    
#     title = serializers.CharField(validators=[validators.validate_title_no_hello, validators.unique_product_title])
#     body = serializers.CharField(source='content')
#     class Meta:
#         model = Product
#         fields = [
#             'owner',
#             'pk',
#             'title',
#             'body',
#             'price',
#             'sale_price',
#             'public',
#             'path',
#             'endpoint',
#         ]
#     def get_my_user_data(self, obj):
#         return {
#             "username": obj.user.username
#         }
    
#     def get_edit_url(self, obj):
#         request = self.context.get('request') # self.request
#         if request is None:
#             return None
#         return reverse("product-edit", kwargs={"pk": obj.pk}, request=request) 
