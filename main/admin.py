from django.contrib import admin
from .models import User
from django.contrib.auth.admin import UserAdmin
from django.forms import TextInput, Textarea

# Register your models here.

class UserAdminConfig(UserAdmin):
    model = User
    
    search_fields = ('email', 'username', 'fullname', 'phone')
    list_filter = ('is_active', 'is_staff')

    ordering = ('-date_joined',)
    list_display = ('email', 'username', 'fullname', 'phone', 'address', 'is_active', 'is_staff')
    
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

admin.site.register(User, UserAdminConfig)