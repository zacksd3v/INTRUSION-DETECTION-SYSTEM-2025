from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

def register(req):
    message = ''

    if req.method == 'POST':
        first_name = req.POST.get('fname')
        last_name = req.POST.get('lname')
        username = req.POST.get('username')
        email = req.POST.get('email')
        password = req.POST.get('password')

        if User.objects.filter(username=username).exists():
            message = 'Username already taken'
        elif User.objects.filter(email=email).exists():
            message = 'Email already exist!'
        else:
            User.objects.create(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password

            )

            return redirect('login')

    return render(req, 'register.html', {'message':message})


def login(req):
    message = ''

    if req.method == 'POST':
        username = req.POST.get('username')
        password = req.POST.get('password')

        user = authenticate(req, username=username, password=password)

        if user is not None:
            login(req, user)
            return redirect('dashboard.html')
        else:
            message = 'Invalid username | password!'


    return render(req, 'login.html', {'message':message})


# @login_required
def dashboard(req):
    return render(req, 'dashboard.html')