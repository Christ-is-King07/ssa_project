from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib import messages
from .forms import UserRegistrationForm
import logging

@login_required
def privacy_settings(request):
    if request.method == 'POST':
        request.user.is_profile_public = request.POST.get('is_profile_public', False)
        request.user.save()
        messages.success(request, 'Privacy settings updated.')
    return render(request, 'users/privacy_settings.html')

@login_required
def delete_account(request):
    if request.method == 'POST':
        request.user.delete()  # Deletes the user's account and all related data
        messages.success(request, 'Your account has been deleted.')
        return redirect('home')
    return render(request, 'users/delete_account.html')

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()  # Automatically hashes the password before saving
            messages.success(request, 'Account created successfully! You can now log in.')
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'users/register.html', {'form': form})

@login_required(login_url='users:login')
def user(request):
    return render(request, "users/user.html")

logger = logging.getLogger(__name__)
def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            logger.info(f"User '{user.username}' logged in successfully.")  # Log successful login
            next_url = request.GET.get('next', reverse("users:user"))
            return HttpResponseRedirect(next_url)
        else:
            logger.warning(f"Failed login attempt for username '{username}'.")  # Log failed login
            messages.error(request, "Invalid Credentials.")
    return render(request, "users/login.html")

def logout_view(request):
    logger.info(f"User '{request.user.username}' logged out.")  # Log logout
    logout(request)
    messages.success(request, "Successfully logged out.")
    return redirect('users:login')