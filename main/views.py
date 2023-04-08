from django.shortcuts import render
from django.http import HttpResponse

from rest_framework import authentication, generics, mixins, permissions
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Doctor, Session, Appointment
from .serializers import DoctorSerializer, SessionSerializer, AppointmentSerializer

# Create your views here.
def home(request):
    return HttpResponse("Hello world!")

@api_view(['GET'])
def home(request, pk=None, *args, **kwargs):
    method = request.method  

    if method == "GET":
        return Response({"data" : "Hello World"})

class DoctorListCreateAPIView(generics.ListCreateAPIView):
    queryset = Doctor.objects.all()
    serializer_class = DoctorSerializer

doctors_create_view = DoctorListCreateAPIView.as_view()

class SessionListCreateAPIView(generics.ListCreateAPIView):
    queryset = Session.objects.all()
    serializer_class = SessionSerializer

sessions_create_view = SessionListCreateAPIView.as_view()

class AppointmentListCreateAPIView(generics.ListCreateAPIView):
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer

appointments_create_view = AppointmentListCreateAPIView.as_view()

# class ProductListCreateAPIView(
#     UserQuerySetMixin,
#     StaffEditorPermissionMixin,
#     generics.ListCreateAPIView):
#     queryset = Product.objects.all()
#     serializer_class = ProductSerializer

#     def perform_create(self, serializer):
#         # serializer.save(user=self.request.user)
#         title = serializer.validated_data.get('title')
#         content = serializer.validated_data.get('content') or None
#         if content is None:
#             content = title
#         serializer.save(user=self.request.user, content=content)
#         # send a Django signal
    
#     # def get_queryset(self, *args, **kwargs):
#     #     qs = super().get_queryset(*args, **kwargs)
#     #     request = self.request
#     #     user = request.user
#     #     if not user.is_authenticated:
#     #         return Product.objects.none()
#     #     # print(request.user)
#     #     return qs.filter(user=request.user)


# product_list_create_view = ProductListCreateAPIView.as_view()

# class ProductDetailAPIView(
#     UserQuerySetMixin, 
#     StaffEditorPermissionMixin,
#     generics.RetrieveAPIView):
#     queryset = Product.objects.all()
#     serializer_class = ProductSerializer
#     # lookup_field = 'pk' ??

# product_detail_view = ProductDetailAPIView.as_view()


# class ProductUpdateAPIView(
#     UserQuerySetMixin,
#     StaffEditorPermissionMixin,
#     generics.UpdateAPIView):
#     queryset = Product.objects.all()
#     serializer_class = ProductSerializer
#     lookup_field = 'pk'

#     def perform_update(self, serializer):
#         instance = serializer.save()
#         if not instance.content:
#             instance.content = instance.title
#             ## 

# product_update_view = ProductUpdateAPIView.as_view()


# class ProductDestroyAPIView(
#     UserQuerySetMixin,
#     StaffEditorPermissionMixin,
#     generics.DestroyAPIView):
#     queryset = Product.objects.all()
#     serializer_class = ProductSerializer
#     lookup_field = 'pk'

#     def perform_destroy(self, instance):
#         # instance 
#         super().perform_destroy(instance)

# product_destroy_view = ProductDestroyAPIView.as_view()

# # class ProductListAPIView(generics.ListAPIView):
# #     '''
# #     Not gonna use this method
# #     '''
# #     queryset = Product.objects.all()
# #     serializer_class = ProductSerializer

# # product_list_view = ProductListAPIView.as_view()

# @api_view(['GET', 'POST'])
# def product_alt_view(request, pk=None, *args, **kwargs):
#     method = request.method  

#     if method == "GET":
#         if pk is not None:
#             # detail view
#             obj = get_object_or_404(Product, pk=pk)
#             data = ProductSerializer(obj, many=False).data
#             return Response(data)
#         # list view
#         queryset = Product.objects.all() 
#         data = ProductSerializer(queryset, many=True).data
#         return Response(data)

#     if method == "POST":
#         # create an item
#         serializer = ProductSerializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             title = serializer.validated_data.get('title')
#             content = serializer.validated_data.get('content') or None
#             if content is None:
#                 content = title
#             serializer.save(content=content)
#             return Response(serializer.data)
#         return Response({"invalid": "not good data"}, status=400)