from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_user, name='login'),
    path('signup/', views.register, name='signup'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('forget_password/', views.forget, name='forget_password'),
    path("result/", views.result, name="result"),
    path("connections/", views.connection_list, name="connection_list"),
    path("upload/", views.upload_page, name="upload_page"),
    path("success/", views.success_page, name="success_page"),

]