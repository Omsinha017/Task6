from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.views import View
from django.conf import settings
from .forms import UserRegsitrationForm
from .models import User
from django.http import Http404, HttpResponse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.hashers import make_password, check_password

import logging
logger = logging.getLogger('django')

class validateUserView:

    def validateUser(email, password):

        try:
            user = User.objects.get(email=email)
            if check_password(password ,user.password):
                logger.info("valid User")
                return user
            else:
                logger.error('Invalid password')
                return None

        except Exception as e:
            logger.error("Email Id does not exist")
            return None


class HomePageView(View):

    def get(self, request):
        try:
            if 'user' in request.session and 'user_uuid' in request.session:
                return render(request, 'base.html', {'current_user': request.session['user'], 'user_uuid' : request.session['user_uuid']})
            return render(request, "base.html")
        except Exception as e:
            logger.error("Error Loading Home Page")


class UserLoginView(View):

    def get(self, request):
        try:
            if 'user' in request.session and 'user_uuid' in request.session:
                return redirect('/')
            return render(request, 'login.html')
        except Exception as e:
            logger.error("Error Loading Login page")

    def post(self, request):
        try:
            user = validateUserView.validateUser(email=request.POST.get('email'), password=request.POST.get('pass'))
            if user and user.is_active:
                logger.info('User logged in')
                request.session['user'] = request.POST.get('email')
                request.session['user_uuid'] = str(User.objects.get(email=request.POST.get('email')).uuid)
                return redirect('/')
            return render(request, 'login.html', {'error':'Account is not activated or wrong credentials'})
        except Exception as e:
            logger.error("Authentication Failed")
            return redirect('login')


class UserSignUpView(View):
    def get(self, request):
        try:
            if 'user' in request.session:
                del request.session['user']
                return render(request, "signup.html", {'form': UserRegsitrationForm})    
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
                user = UserRegisterForm.save(commit=False)
                user.password = make_password(request.POST.get('password'))
                user.save()
                
                current_site = get_current_site(request)
                url = f"http://{current_site.domain}/activate_account/{user.uuid}"
                send_mail(
                'Account Activation Link',
                'Your Account activation Link is : ' + url,
                settings.EMAIL_HOST_USER,
                [request.POST.get("email")],
                fail_silently=False,
                )
                return redirect('/login/')
            else:
                context['message'] = UserRegisterForm.errors
            return render(request, "signup.html", context)
        except Exception as e:
            logger.error("Form Error")


class UserlogoutView(View):
    def get(self, request):
        try:
            del request.session['user']
            del request.session['user_uuid']
            logger.info('User logged out')
        except Exception as e:
            logger.info('Error during logout')
            return redirect('/')
        return redirect('/')


class UserAccountActivationView(View):

    def get(self, request, uid):
        try:
            user = User.objects.get(uuid=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user and user.is_active is False:
            user.is_active = True
            user.save()
            return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
        else:
            return HttpResponse('Activation link is invalid!')


class UserPasswordChangeView(View):

    def get(self, request, uid):
        context = {
            'current_user' : request.session['user'],
            'user_uuid' : request.session['user_uuid'],
        }
        try:
            if 'user' in request.session and 'user_uuid' in request.session:
                try:
                    User.objects.get(email=request.session['user'], uuid=uid)
                    return render(request, "change-password.html", context)
                except Exception as e:
                    logger.error("Invalid User")
                    del request.session['user']
                    del request.session['user_uuid']
                    return redirect("/")
        except Exception as e:
            logger.error("Wrong URL")
            return redirect("/")

    def post(self, request, uid):
        context = {
            'current_user' : request.session['user'],
            'user_uuid' : request.session['user_uuid'],
        }
        try:
            if request.POST.get("password") == request.POST.get('confirm_password'):
                if len(request.POST.get('password')) >= 8:
                    try:
                        user = User.objects.get(email=request.session['user'], uuid=uid)
                        if not check_password(request.POST.get('old_password'), user.password):
                            context["message"] = "Your old password is incorrect"
                            logger.error("Old password is incorrect")
                            return render(request, "change-password.html", context)

                        if check_password(request.POST.get('password'), user.password):
                            context["message"] = "Enter a new password"
                            logger.error("New password is required")
                            return render(request, "change-password.html", context)

                        user.password = make_password(
                            request.POST.get("password"))
                        user.save()
                        logger.info("User Changed his password")
                        del request.session['user']
                        del request.session['user_uuid']
                        return redirect('/login/')
                    except Exception as e:
                        logger.error("No User with this uuid Exists")
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
                user.forget_link = True
                user.save()
                context["message"] = "Reset link has been sent to the registered mail Id"
                logger.info("Reset Email Sent to the registerd Mail Id")
                return render(request, "forget-password.html", context)
        except Exception as e:
            context["message"] = "No user with that email Id exists"
            logger.error("No user with that email Id exists")
            return render(request, "forget-password.html", context)


class UserPasswordResetView(View):

    def get(self, request, uid):
        try:
            user = User.objects.get(uuid=uid)
            if user.forget_link == True:
                return render(request, "resetpassword.html")

            logger.error("User forget link field is false")
            return HttpResponse('Link is not working')
        except Exception as e:
            logger.error("Wrong URL")
            raise Http404("Wrong Url")

    def post(self, request, uid):
        context = {}
        try:
            user = User.objects.get(uuid=uid)
            if user.forget_link:
                if request.POST.get("password") == request.POST.get('confirm_password'):
                    if len(request.POST.get('password')) >= 8:
                        try:
                            user = User.objects.get(uuid=uid)
                            if check_password(request.POST.get('password'), user.password):
                                context["message"] = "Enter a new password"
                                logger.error("New password is required")
                                return render(request, "resetpassword.html", context)
                            user.password = make_password(
                                request.POST.get("password"))
                            user.forget_link = False
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

            logger.error("User forget link field is false")
            return HttpResponse('Link is not working')
        except Exception as e:
            logger.error("Wrong URL")
            raise Http404("Wrong Url")
