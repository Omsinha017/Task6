from .models import User
from django import forms
from django.core.exceptions import ValidationError

class UserRegsitrationForm(forms.ModelForm):
    confirm_password = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        model = User
        fields = ('first_name','last_name','email','password', 'confirm_password')
        widgets = {
            'password': forms.PasswordInput() 
        }

    def clean(self):
        SpecialSym =['$', '@', '#', '%']

        if not any(char.isdigit() for char in self.cleaned_data.get('password')):
            raise ValidationError("Password should have at least one numeral")

        if not any(char.isupper() for char in self.cleaned_data.get('password')):
            raise ValidationError('Password should have at least one uppercase letter')

        if not any(char.islower() for char in self.cleaned_data.get('password')):
            raise ValidationError("Password should have at least one lowercase letter")

        if not any(char in SpecialSym for char in self.cleaned_data.get('password')):
            raise ValidationError("Password should have at least one of the symbols $@#")

        if self.cleaned_data.get('password') != self.cleaned_data.get('confirm_password'):
            raise ValidationError("Passwords don't match")
        
        if len(self.cleaned_data.get('password')) < 8 :
            raise ValidationError("Minimum password length is 8")

        if User.objects.filter(email=self.cleaned_data.get('email')).exists():
            raise ValidationError("Email aready already in use")

        return self.cleaned_data


