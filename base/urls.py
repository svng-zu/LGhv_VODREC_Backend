"""
URL configuration for base project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from service.views import SignupAPIView, LoginView
from service.views import login, test, status_check, login_suc

urlpatterns = [
    path("admin/", admin.site.urls),
    path('login/', login, name = 'login'),
    path('', test, name = 'test_login'),
    path('scheck/', status_check, name = 'token_check'),
    # path("signup/", SignupAPIView.as_view(), name = 'signup'),
    path('login2/', LoginView.as_view(), name = 'login2'),
    path('login_suc/', login_suc, name = 'login_success'),
]
