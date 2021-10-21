from .models import User
from django import forms

class UserRegsitrationForm(forms.ModelForm):
    confirm_password = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        model = User
        fields = ('first_name','last_name','email','password', 'confirm_password')
        widgets = {
            'password': forms.PasswordInput() 
        }

    def clean(self):

        if self.cleaned_data.get('password') != self.cleaned_data.get('confirm_password'):
            raise forms.ValidationError("Passwords don't match")
        
        if len(self.cleaned_data.get('password')) < 8 :
            raise forms.ValidationError("Minimum password length is 8")

        if User.objects.get(email=self.cleaned_data.get('email')):
            raise forms.ValidationError("User with this email already exists")

        return self.cleaned_data

    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)
