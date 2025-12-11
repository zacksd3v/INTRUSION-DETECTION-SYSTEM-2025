import sweetify
import joblib
import numpy as np
# from .forms import NidsForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

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
            return redirect('dashboard')
        else:
            sweetify.toast(req, 'Invalid Username | Password!', icon='warning')


    return render(req, 'login.html')


# @login_required
# def dashboard(req):
#     sweetify.toast(req, 'Welcome To NIDS 2025', icon='success')
#     return render(req, 'dashboard.html')
    


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


# Load ML files once
model = joblib.load("model.pkl")
encoders = joblib.load("encoders.pkl")

# @login_required
def dashboard(request):
    if request.method == "POST":
        # Collect ALL 41 features from your form
        # (same order as the dataset)
        data = [
            float(request.POST.get("duration")),
            encoders["protocol_type"].transform([request.POST.get("protocol_type")])[0],
            encoders["service"].transform([request.POST.get("service")])[0],
            encoders["flag"].transform([request.POST.get("flag")])[0],
            float(request.POST.get("src_bytes")),
            float(request.POST.get("dst_bytes")),
            float(request.POST.get("land")),
            float(request.POST.get("wrong_fragment")),
            float(request.POST.get("urgent")),
            float(request.POST.get("hot")),
            float(request.POST.get("num_failed_logins")),
            float(request.POST.get("logged_in")),
            float(request.POST.get("num_compromised")),
            float(request.POST.get("root_shell")),
            float(request.POST.get("su_attempted")),
            float(request.POST.get("num_root")),
            float(request.POST.get("num_file_creations")),
            float(request.POST.get("num_shells")),
            float(request.POST.get("num_access_files")),
            float(request.POST.get("num_outbound_cmds")),
            float(request.POST.get("is_hot_login")),
            float(request.POST.get("is_guest_login")),
            float(request.POST.get("count")),
            float(request.POST.get("srv_count")),
            float(request.POST.get("serror_rate")),
            float(request.POST.get("srv_serror_rate")),
            float(request.POST.get("rerror_rate")),
            float(request.POST.get("srv_rerror_rate")),
            float(request.POST.get("same_srv_rate")),
            float(request.POST.get("diff_srv_rate")),
            float(request.POST.get("srv_diff_host_rate")),
            float(request.POST.get("dst_host_count")),
            float(request.POST.get("dst_host_srv_count")),
            float(request.POST.get("dst_host_same_srv_rate")),
            float(request.POST.get("dst_host_diff_srv_rate")),
            float(request.POST.get("dst_host_same_src_port_rate")),
            float(request.POST.get("dst_host_srv_diff_host_rate")),
            float(request.POST.get("dst_host_serror_rate")),
            float(request.POST.get("dst_host_srv_serror_rate")),
            float(request.POST.get("dst_host_rerror_rate")),
            float(request.POST.get("dst_host_srv_rerror_rate")),
        ]

        # Convert to 2D array
        data = np.array(data).reshape(1, -1)

        # Predict
        pred = model.predict(data)[0]

        # Reverse-encode attack label
        attack_label = encoders["attack"].inverse_transform([pred])[0]

        return render(request, "result.html", {"result": attack_label})

    sweetify.toast(request, 'Welcome To NIDS 2025', icon='success')
    return render(request, "dashboard.html")



def result(req):
    sweetify.toast(req, 'Predicted Successfully!', icon='success')
    return render(req, 'result.html')
