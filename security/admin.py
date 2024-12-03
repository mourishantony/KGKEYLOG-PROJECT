from django.contrib import admin
from .models import Staff,Key,Temporary,History
# Register your models here.
admin.site.register(Temporary)
admin.site.register(Staff)
admin.site.register(Key)
admin.site.register(History)