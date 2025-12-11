from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_user, name='login'),
    path('signup/', views.register, name='signup'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('forget_password/', views.forget, name='forget_password'),
    path("result/", views.result, name="result"),
    # path('upload', views.upload, name='upload'),
    path("upload_csv/", views.upload_csv, name="upload_csv"),
    path("uploaded_result/", views.uploaded_result, name="uploaded_result"),

]