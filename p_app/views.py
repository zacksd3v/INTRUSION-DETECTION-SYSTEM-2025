import sweetify
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

def register(req):

    if req.method == 'POST':
        first_name = req.POST.get('fname')
        last_name = req.POST.get('lname')
        username = req.POST.get('username')
        email = req.POST.get('email')
        password = req.POST.get('password')

        if User.objects.filter(username=username).exists():
            sweetify.error(req, 'Username already taken', button='OK')
        elif User.objects.filter(email=email).exists():
            sweetify.error(req, 'Email already exist!', button='OK')

        else:
            User.objects.create(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password

            )

            sweetify.success(req, 'Registration Successfully!', button='Ok')

            return redirect('login')

    return render(req, 'register.html')


def login(req):

    if req.method == 'POST':
        username = req.POST.get('username')
        password = req.POST.get('password')

        user = authenticate(req, username=username, password=password)

        if user is not None:
            login(req, user)
            return redirect('dashboard.html')
        else:
            sweetify.error(req, 'Invalid Username | Password!', button='OK')


    return render(req, 'login.html')


# @login_required
def dashboard(req):
    sweetify.success(req, 'Welcome To NIDS 2025', button='OK')
    return render(req, 'dashboard.html')