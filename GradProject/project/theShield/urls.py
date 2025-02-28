from django.urls import path
from . import views

urlpatterns = [
    path('home', views.home, name='home'),
    path('login_signup', views.login_signup, name='login_signup'),
    path('user', views.user, name='user'),
    path('logout', views.logout, name='logout'),
]