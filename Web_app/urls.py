from Web_app import views
from django.urls import path


urlpatterns = [
    path('', views.HomePageView.as_view(), name='HomePage'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('signup/', views.UserSignUpView.as_view(), name='signup'),
    path('logout/', views.UserlogoutView.as_view(), name='logout'),
    path('change_password/<slug:uid>/', views.UserPasswordChangeView.as_view(), name='change_password'),
    path('reset_password/<slug:uid>/', views.UserPasswordResetView.as_view(), name='reset_password'),
    path('forgot_password/', views.UserPasswordForgetView.as_view(), name='forgot'),
    path('activate_account/<slug:uid>/', views.UserAccountActivationView.as_view(), name='activate_account'),
]