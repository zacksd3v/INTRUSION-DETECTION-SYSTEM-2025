from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login, name='login'),
    path('signup/', views.register, name='signup'),
    path('dashboard/', views.dashboard, name='dashboard')
]