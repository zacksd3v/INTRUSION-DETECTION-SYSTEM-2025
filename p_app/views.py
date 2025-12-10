import sweetify
# import joblib
# import numpy as np
# from .forms import NidsForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
# from django.contrib.auth.forms import AuthenticationForm

def register(req):

    if req.method == 'POST':
        first_name = req.POST.get('fname')
        last_name = req.POST.get('lname')
        username = req.POST.get('username')
        email = req.POST.get('email')
        password = req.POST.get('password')

        if User.objects.filter(username=username).exists():
            sweetify.toast(req, 'Username already taken', icon='warning')
        elif User.objects.filter(email=email).exists():
            sweetify.toast(req, 'Email already exist!', icon='warning')

        else:
            User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password

            )

            sweetify.toast(req, 'Registration Successfully!', icon='success')

            return redirect('login')

    return render(req, 'register.html')


def login_user(req):

    if req.method == 'POST':
        username = req.POST.get('username')
        password = req.POST.get('password')

        user = authenticate(req, username=username, password=password)

        if user is not None:
            login(req, user)
            sweetify.toast(req, 'Login Successfully!', icon='success')
            # return render(req, 'dashboard.html')
            return redirect('dashboard')
        else:
            sweetify.toast(req, 'Invalid Username | Password!', icon='warning')


    return render(req, 'login.html')


@login_required
def dashboard(req):
    sweetify.toast(req, 'Welcome To NIDS 2025', icon='success')
    return render(req, 'dashboard.html')
    
    # prediction = None

    # if req.method == 'POST':
    #     form = NidsForm(req.POST)

    #     if form.is_valid():
    #         data = list(form.cleaned_data.values()) # convert to array
    #         data = np.array(data).reshape(1, -1)

    #         # model prediction
    #         result = model.predict(data)[0]

    #         if result == 0:
    #             prediction = sweetify.success(req, 'NORMAL TRAFFIC', button='OK')
    #         else:
    #             prediction = sweetify.warning(req, 'INTRUSION DETECTED!!', button='OK')

    # else:
    #     form = NidsForm()

    # sweetify.toast(req, 'Welcome To NIDS 2025', icon='success')
    # return render(req, 'dashboard.html', {
    #     "form": form,
    #     "prediction": prediction,
    # })


def forget(req):

    if req.method == 'POST':
        update_psswd = req.POST.get('update')

        if update_psswd == req.POST.get('update'):
            sweetify.toast(req, 'Password Updated Successfully!', icon='success')
            return render(req, 'login.html')
        else:
            sweetify.toast(req, 'Unable To Update Password!', icon='warning')
            return render(req, 'forget.html')

    return render(req, 'forget.html')

def logout_view(request):
    logout(request)
    sweetify.toast(request, "You have been logged out.", icon='warning')
    return redirect("login")