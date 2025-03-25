from django.urls import path
from .views import RegisterView, LoginView, UserDetailsView, LogoutView, CsrfTokenView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('me/', UserDetailsView.as_view(), name='me'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('csrf-token/', CsrfTokenView.as_view(), name='csrf-token'),
]
