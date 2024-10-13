
from rest_framework import serializers
from .models import *

class url_detectionSerializer(serializers.ModelSerializer):
    # This will return specific fields from the related User model
    author_id = serializers.CharField(source='author.id', read_only=True)
    author_username = serializers.CharField(source='author.username', read_only=True)
    author_email = serializers.EmailField(source='author.email', read_only=True)

    class Meta:
        model = url_detection
        fields = ['id', 'url', 'result', 'date_posted', 'author_username', 'author_email', 'author_id']

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        if User.objects.filter(username=validated_data['username']).exists():
            raise serializers.ValidationError({"username": "This username is already taken."})

        if User.objects.filter(email=validated_data['email']).exists():
            raise serializers.ValidationError({"email": "This email is already registered."})

        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user

