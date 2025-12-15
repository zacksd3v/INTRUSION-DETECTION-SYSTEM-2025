from django import forms

class UploadTrafficForm(forms.Form):
    file = forms.FileField(label="Upload Traffic File")
