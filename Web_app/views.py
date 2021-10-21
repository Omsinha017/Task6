from django.contrib.auth import login
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.views import View
from django.conf import settings
from django.contrib.auth import login, logout
from .forms import UserRegsitrationForm
from .models import User
from django.http import HttpResponse
from django.contrib.auth.hashers import make_password
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404
from django.contrib.sites.shortcuts import get_current_site
import logging
logger = logging.getLogger('django')


def validateUser(email, password):
    try:
        user = User.objects.get(email=email)
        if user.check_password(password):
            logger.info("valid User")
            return user
        logger.error('Invalid password')
        return None

    except Exception as e:
        logger.error("Email Id does not exist")
        return None


class HomePageView(View):

    def get(self, request):
        try:
            return render(request, 'base.html')
        except Exception as e:
            logger.error("Error Loading Home Page")


class UserLoginView(View):
    def get(self, request):
        try:
            return render(request, 'login.html')
        except Exception as e:
            return HttpResponse(e)

            logger.error("Error Loading Login page")

    def post(self, request):
        try:
            user = validateUser(email=request.POST.get(
                'email'), password=request.POST.get('pass'))
            try:
                if user:
                    login(request, user)
                    logger.info('User logged in')
                    return redirect('HomePage')
                logger.error('No User with that emailId exists')
            except Exception as e:
                logger.error("Login error")
                return HttpResponse(e)
        except Exception as e:
            logger.error("Authentication Failed")
            return redirect('login')


class UserSignUpView(View):
    def get(self, request):
        try:
            return render(request, "signup.html", {'form': UserRegsitrationForm})
        except Exception as e:
            logger.error("Error Loading Signup page")

    def post(self, request):
        context = {
            'form': UserRegsitrationForm
        }
        try:
            UserRegisterForm = UserRegsitrationForm(request.POST)
            if UserRegisterForm.is_valid():
                # user = UserRegisterForm.save()
                email = request.POST.get('email')
                password = request.POST.get('password')
                firstName = request.POST.get('first_name')
                lastName = request.POST.get('last_name')
                User.objects.create_user(email, password, firstName, lastName)
                # user.save()

                context['message'] = "Account has been created successfully. Activation link has been sent to your email address."
            else:
                context['message'] = UserRegisterForm.errors
            return render(request, "signup.html", context)
        except Exception as e:
            return HttpResponse(e)


# class activateAccount(View):

#     def get(self, request, uidb64, token):
#         try:
#             uid = force_text(urlsafe_base64_decode(uidb64))
#             user = User.objects.get(pk=uid)
#         except(TypeError, ValueError, OverflowError, User.DoesNotExist):
#             user = None
#         if user is not None and account_activation_token.check_token(user, token):
#             user.is_active = True
#             user.save()
#             return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
#         else:
#             return HttpResponse('Activation link is invalid!')


class UserlogoutView(View):
    def get(self, request):
        try:
            logout(request)
            logger.info("User logged Out")
            return redirect("/")
        except Exception as e:
            logger.error("Error Logging out the user")


class UserPasswordChangeView(LoginRequiredMixin, View):
    login_url = '/login/'

    def get(self, request, uid):
        try:
            user = User.objects.get(uuid=uid)
            return render(request, "change-password.html")
        except Exception as e:
            logger.error("Wrong URL")
            raise Http404("Wrong Url")

    def post(self, request, uid):
        context = {}
        try:
            if request.POST.get("password") == request.POST.get('confirm_password'):
                if len(request.POST.get('password')) >= 8:
                    try:
                        user = User.objects.get(uuid=uid)
                        if not user.check_password(request.POST.get('old_password')):
                            context["message"] = "Your old password is incorrect"
                            logger.error("Old password is incorrect")
                            return render(request, "change-password.html", context)
                        if user.check_password(request.POST.get('password')):
                            context["message"] = "Enter a new password"
                            logger.error("New password is required")
                            return render(request, "change-password.html", context)
                        user.password = make_password(
                            request.POST.get("pass1"))
                        user.save()
                        logger.info("User Changed his password")
                        return redirect('/login/')
                    except Exception as e:
                        logger.error("No User with that uuid Exists")
                        raise Http404("Wrong Url")

                context['message'] = "Password length must be 8"
                logger.info("Password Length Must Be 8")
                return render(request, "change-password.html", context)

            context['message'] = "Passowrds don't match"
            logger.info("Passwords did not match")
            return render(request, "change-password.html", context)

        except Exception as e:
            logger.error("Wrong URL")
            raise Http404("Wrong Url")

class UserPasswordForgetView(View):
    def get(self, request):
        try:
            return render(request, "forget-password.html")
        except Exception as e:
            logger.error("Error rendering out Forgot Password page")
    
    def post(self, request):
        context = {}
        try:
            user = User.objects.get(email=request.POST.get("email"))
            if user :
                current_site = get_current_site(request)
                url = f"http://{current_site.domain}/reset_password/{user.uuid}"
                send_mail(
                'Password Reset Link',
                'Your Password reset Link is : ' + url,
                settings.EMAIL_HOST_USER,
                [request.POST.get("email")],
                fail_silently=False,
            )
                context["message"] = "Reset link has been sent to the registered mail Id"
                return render(request, "forget-password.html", context)
        except Exception as e:
            context["message"] = "No user with that email Id exists"
            logger.error("No user with that email Id exists")
            return render(request, "forget-password.html", context)


class UserPasswordResetView(View):

    def get(self, request, uid):
        try:
            user = User.objects.get(uuid=uid)
            return render(request, "resetpassword.html")
        except Exception as e:
            logger.error("Wrong URL")
            raise Http404("Wrong Url")

    def post(self, request, uid):
        context = {}
        try:
            if request.POST.get("password") == request.POST.get('confirm_password'):
                if len(request.POST.get('password')) >= 8:
                    try:
                        user = User.objects.get(uuid=uid)
                        if user.check_password(request.POST.get('password')):
                            context["message"] = "Enter a new password"
                            logger.error("New password is required")
                            return render(request, "resetpassword.html", context)
                        user.password = make_password(
                            request.POST.get("password"))
                        user.save()
                        return redirect('/login/')
                    except Exception as e:
                        logger.error("No User with that uuid Exists")
                        raise Http404("Wrong Url")

                context['message'] = "Password length must be 8"
                logger.info("Password Length Must Be 8")
                return render(request, "resetpassword.html", context)

            context['message'] = "Passowrds don't match"
            logger.info("Passwords did not match")
            return render(request, "resetpassword.html", context)

        except Exception as e:
            logger.error("Wrong URL")
            raise Http404("Wrong Url")
            
