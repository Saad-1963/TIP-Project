from django.urls import path
from . import views
from .views import *
from .views import CustomAuthToken
urlpatterns = [
    path('', views.about),
    path('prediction_api/', views.prediction_api, name='prediction_api'),
    path('url-detections/', url_detectionListView.as_view(), name='url-detection-list'),
    path('api/login/', CustomAuthToken.as_view(), name='login'),
    path('api/signup/', UserRegistrationView.as_view(), name='signup'),

    ]



