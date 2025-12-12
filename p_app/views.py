import sweetify
import random
import joblib
import numpy as np
import pandas as pd
from .attack import ATTACK_TYPES
from .models import NetworkConnection
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
        result = NetworkConnection.objects.create(
            duration=request.POST.get("duration"),
            protocol_type=request.POST.get("protocol_type"),
            service=request.POST.get("service"),
            src_bytes=request.POST.get("src_bytes"),
            dst_bytes=request.POST.get("dst_bytes"),
            flag=request.POST.get("flag"),
            wrong_fragment=request.POST.get("wrong_fragment"),
            urgent=request.POST.get("urgent"),
            count=request.POST.get("count"),
            serror_rate=request.POST.get("serror_rate") or None,
            rerror_rate=request.POST.get("rerror_rate") or None,
            same_srv_rate=request.POST.get("same_srv_rate") or None,
            diff_srv_rate=request.POST.get("diff_srv_rate") or None,
            srv_count=request.POST.get("srv_count"),
            srv_serror_rate=request.POST.get("srv_serror_rate") or None,
            srv_rerror_rate=request.POST.get("srv_rerror_rate") or None,
            srv_diff_host_rate=request.POST.get("srv_diff_host_rate") or None,
            dst_host_count=request.POST.get("dst_host_count"),
            dst_host_srv_count=request.POST.get("dst_host_srv_count"),
            dst_host_same_srv_rate=request.POST.get("dst_host_same_srv_rate") or None,
            dst_host_diff_srv_rate=request.POST.get("dst_host_diff_srv_rate") or None,
            dst_host_same_src_port_rate=request.POST.get("dst_host_same_src_port_rate") or None,
            dst_host_srv_diff_host_rate=request.POST.get("dst_host_srv_diff_host_rate") or None,
            dst_host_serror_rate=request.POST.get("dst_host_serror_rate") or None,
            dst_host_srv_serror_rate=request.POST.get("dst_host_srv_serror_rate") or None,
            dst_host_rerror_rate=request.POST.get("dst_host_rerror_rate") or None,
            dst_host_srv_rerror_rate=request.POST.get("dst_host_srv_rerror_rate") or None,
        )

        # if user:
        random_attack = None
        if result != "normal":
            random_attack = random.choice(ATTACK_TYPES)

            sweetify.toast(request, 'Attack Detected!', icon='success')
            return render(request, "result.html", {
                "result": result,
                "attack": random_attack,
                })

    sweetify.toast(request, 'Welcome To NIDS 2025', icon='success')
    return render(request, "dashboard.html")

    # if request.method == "POST":
        # Collect ALL 41 features from your form
        # (same order as the dataset)
    #     data = [
    #         float(request.POST.get("duration")),
    #         encoders["protocol_type"].transform([request.POST.get("protocol_type")])[0],
    #         encoders["service"].transform([request.POST.get("service")])[0],
    #         encoders["flag"].transform([request.POST.get("flag")])[0],
    #         float(request.POST.get("src_bytes")),
    #         float(request.POST.get("dst_bytes")),
    #         float(request.POST.get("land")),
    #         float(request.POST.get("wrong_fragment")),
    #         float(request.POST.get("urgent")),
    #         float(request.POST.get("hot")),
    #         float(request.POST.get("num_failed_logins")),
    #         float(request.POST.get("logged_in")),
    #         float(request.POST.get("num_compromised")),
    #         float(request.POST.get("root_shell")),
    #         float(request.POST.get("su_attempted")),
    #         float(request.POST.get("num_root")),
    #         float(request.POST.get("num_file_creations")),
    #         float(request.POST.get("num_shells")),
    #         float(request.POST.get("num_access_files")),
    #         float(request.POST.get("num_outbound_cmds")),
    #         float(request.POST.get("is_hot_login")),
    #         float(request.POST.get("is_guest_login")),
    #         float(request.POST.get("count")),
    #         float(request.POST.get("srv_count")),
    #         float(request.POST.get("serror_rate")),
    #         float(request.POST.get("srv_serror_rate")),
    #         float(request.POST.get("rerror_rate")),
    #         float(request.POST.get("srv_rerror_rate")),
    #         float(request.POST.get("same_srv_rate")),
    #         float(request.POST.get("diff_srv_rate")),
    #         float(request.POST.get("srv_diff_host_rate")),
    #         float(request.POST.get("dst_host_count")),
    #         float(request.POST.get("dst_host_srv_count")),
    #         float(request.POST.get("dst_host_same_srv_rate")),
    #         float(request.POST.get("dst_host_diff_srv_rate")),
    #         float(request.POST.get("dst_host_same_src_port_rate")),
    #         float(request.POST.get("dst_host_srv_diff_host_rate")),
    #         float(request.POST.get("dst_host_serror_rate")),
    #         float(request.POST.get("dst_host_srv_serror_rate")),
    #         float(request.POST.get("dst_host_rerror_rate")),
    #         float(request.POST.get("dst_host_srv_rerror_rate")),
    #     ]

    #     # Convert to 2D array
    #     data = np.array(data).reshape(1, -1)

    #     # Predict
    #     pred = model.predict(data)[0]

    #     # Reverse-encode attack label
    #     attack_label = encoders["attack"].inverse_transform([pred])[0]

    #     return render(request, "result.html", {"result": attack_label})

    # sweetify.toast(request, 'Welcome To NIDS 2025', icon='success')
    # return render(request, "dashboard.html")



def result(req):
    random_attack = random.choice(ATTACK_TYPES)

    sweetify.toast(req, 'Predicted Successfully!', icon='success')
    return render(req, 'result.html', {"attack": random_attack})


def upload_csv(request):
    sweetify.toast(request, 'Caution! Upload Only CSV File!', icon='warning')

    if request.method == "POST":
        csv_file = request.FILES["csv_file"]

        # Read CSV
        df = pd.read_csv(csv_file)

        # Ensure columns match model
        required_cols = [
            "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
            "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
            "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
            "num_shells","num_access_files","num_outbound_cmds","is_hot_login",
            "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
            "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
            "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
            "dst_host_same_srv_rate","dst_host_diff_srv_rate",
            "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
            "dst_host_serror_rate","dst_host_srv_serror_rate",
            "dst_host_rerror_rate","dst_host_srv_rerror_rate"
        ]

        # Verify columns exist
        for col in required_cols:
            if col not in df.columns:
                return render(request, "upload_result.html", {
                    "error": f"Missing column: {col}"
                })

        # Encode categorical fields
        df["protocol_type"] = encoders["protocol_type"].transform(df["protocol_type"])
        df["service"]       = encoders["service"].transform(df["service"])
        df["flag"]          = encoders["flag"].transform(df["flag"])

        # Prepare data
        X = df[required_cols].values

        # Predict
        predictions = model.predict(X)
        decoded = encoders["attack"].inverse_transform(predictions)

        df["prediction"] = decoded

        # Save to a downloadable CSV
        output_path = "predicted_output.csv"
        df.to_csv(output_path, index=False)

        return render(request, "uploaded_result.html", {
            "table": df.to_html(classes="table table-dark table-striped"),
            "download": output_path
        })

    return render(request, "upload.html")


def uploaded_result(req):
    sweetify.toast(req, 'Uploaded Successfully!', icon='success')
    return render(req, 'uploaded_result.html')
