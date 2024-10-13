from django.shortcuts import render
from django.contrib.auth.models import User
from rest_framework import generics
from .models import *
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import *
import numpy as np # linear algebra
import os
from urllib.parse import urlparse, parse_qs
import re
import ipaddress
import joblib
import xgboost as xgb
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework import status

# Example type_mapping
type_mapping = {
    'malware': 3,
    'defacement': 2,
    'phishing': 1,
    'benign': 0
}
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# model_path = os.path.join(BASE_DIR, 'api', 'ML_models', 'XG_boost_model.pkl')
XG_model = joblib.load(os.path.join(BASE_DIR, 'api', 'ML_models', 'XG_boost_model.pkl'))


class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        print("res",request.data)
        # Get the token using the default authentication process
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)

        # Return token and user details in response
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'username': user.username,
            'email': user.email,
        })



class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)






def get_url_len(url):
    return len(url)
def extract_domain_length(url):
    try:
        # Add 'http://' if no scheme is present
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Return the length of the domain
        return len(domain) if domain else 0

    except Exception as e:
        return 0

def check_http(url):
    if url.startswith('http://'):
        return 1
    else:
        return 0

def check_https(url):
    if url.startswith('https://'):
        return 1
    else:
        return 0
def count_dots(url):
    return url.count('.')
def count_dashes(url):
    return url.count('-')
def count_underscores(url):
    return url.count('_')
def count_ques(url):
    return url.count('?')
def count_url_parameters(url):
    # Parse the URL using urlparse
    parsed_url = urlparse(url)

    # Extract the query part of the URL
    query = parsed_url.query

    # Parse the query parameters using parse_qs
    parameters = parse_qs(query)

    # Return the number of parameters
    return len(parameters)
def count_slashes(url):
    return url.count('/')
def count_special_chars(url):
    non_alpha_num = re.findall(r'\W',url)
    return len(non_alpha_num)
def count_digits(url):
    digits = re.findall(r'\d',url)
    return len(digits)
def count_letters(url):
    letters=re.findall(r'[a-zA-Z]',url)
    return len(letters)
def has_ip_address(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.hostname:
            ip = ipaddress.ip_address(parsed_url.hostname)
            return isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
    except ValueError:
        pass
    return 0
def check_php_in_url(url):
    # Check if the term 'php' is present in the URL (case-insensitive)
    if 'php' in url.lower():
        return 1
    else:
        return 0
def check_html_in_url(url):
    # Check if the term 'php' is present in the URL (case-insensitive)
    if 'html' in url.lower():
        return 1
    else:
        return 0

tld_list = [
    '.tk', '.buzz', '.xyz', '.top', '.ga', '.ml', '.info', '.cf', '.gq', '.icu', '.wang', '.live', '.host', '.shop' , '.top', '.icu', '.vip', '.id', '.cc', '.br', '.ci', '.zw', '.sx', '.mw'
]
def check_mal_tld(url):
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc.lower()

    if any(netloc.endswith(tld) for tld in tld_list):
        return 1
    return 0
def is_shortened_url(url):
    shortened_services = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
        "is.gd", "adf.ly", "bit.do", "cutt.ly", "v.gd", "shorte.st",
        "bl.ink", "x.co", "s.id", "trib.al"
    ]

    parsed_url = urlparse(url)
    netloc = parsed_url.netloc.lower()

    if any(service in netloc for service in shortened_services):
        return 1
    return 0
def prepare_input(url):
    features = []

    feature_extractors = [
        get_url_len,
        extract_domain_length,
        check_http,
        check_https,
        count_dots,
        count_dashes,
        count_underscores,
        count_ques,
        count_slashes,
        count_special_chars,
        count_digits,
        count_letters,
        has_ip_address,
        count_url_parameters,
        check_php_in_url,
        check_html_in_url,
        check_mal_tld,
        is_shortened_url
    ]

    for feature_extractor in feature_extractors:
        features.append(feature_extractor(url))

    x_test = np.array(features).reshape(1, -1)

    return x_test
def predict(url,model1):
    x_test = prepare_input(url)
    predictions = model1.predict(x_test)
    reverse_type_mapping = {v: k for k, v in type_mapping.items()}
    predicted_class_label = reverse_type_mapping[predictions[0]]
    return predicted_class_label
# def home(request):
#     context = {
#         'posts': User.objects.all()
#     }
#     return render(request, 'blog/home.html', context)
def about(request):
    a=User.objects.all()
    print(a)
    return render(request, 'api/about.html')

@api_view(['GET'])
def prediction_api(request):
    # Retrieve 'p_no' from query parameters (this is the URL)
    url = request.GET.get('url', '')
    print('11 , ',url ,'  1 111 ')
    if not url:
        return Response({'error': 'URL parameter (p_no) missing'}, status=400)

    u_id = request.GET.get('u_id', '')
    if not u_id:
        return Response({'error': 'User ID (d_id) parameter missing'}, status=400)

    # Ensure that 'u_id' is a valid integer (optional step)
    try:
        u_id = int(u_id)
    except ValueError:
        return Response({'error': 'User ID (d_id) must be an integer'}, status=400)

    # Call the predict function with the provided URL
    p = predict(url, XG_model)  # Use the URL from the request

    # Get the user object
    try:
        user = User.objects.get(id=u_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)
    # Save the result to the url_detection model
    obj = url_detection()
    obj.author = user
    obj.result = p
    obj.url = url
    obj.save()
    # Serialize the result and return it
    serializer = url_detectionSerializer(obj)
    return Response(serializer.data)


class url_detectionListView(generics.ListAPIView):
    queryset = url_detection.objects.all()  # Query all records from the table
    serializer_class = url_detectionSerializer
