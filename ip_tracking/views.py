from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect
from ratelimit.decorators import ratelimit

@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
@csrf_protect
def login_view(request):
    """
    Login view with rate limiting
    """
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')
    else:
        form = AuthenticationForm()
    
    return render(request, 'login.html', {'form': form})

# Add this view for anonymous users with stricter rate limiting
@ratelimit(key='ip', rate='5/m', method='ALL', block=True)
def public_api_view(request):
    """
    Public API view with rate limiting for anonymous users
    """
    return render(request, 'api_response.html')