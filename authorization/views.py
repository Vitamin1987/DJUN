from random import choices

from django.contrib.auth import get_user_model, authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.http import HttpResponse
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from authorization.constants import ROLE_ADMIN, ROLE_USER, ROLE_MODERATOR


class HealthApiView(APIView):

    permission_classes = (IsAuthenticated,)
    # permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):

        print("Get request was sent by:", request.user)

        return HttpResponse("Ok!")


class LoginApiView(APIView):

    permission_classes = (AllowAny,)

    class InputSerializer(serializers.Serializer):
        username = serializers.CharField(max_length=150)
        password = serializers.CharField(max_length=128)


    def post(self, request, *args, **kwargs):
        serializer = self.InputSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            print(serializer.validated_data)

            user = authenticate(
                request,
                username=serializer.validated_data.get("username"),
                password=serializer.validated_data.get("password")
            )

            if user:
                login(request, user)
                print("user:", user.username)
            else:
                return Response({"message": "Invalid credentials!"}, status=401)

        return Response({"message": "Login successful!"})


class LogoutApiView(APIView):

    def post(self, request, *args, **kwargs):
        logout(request)

        return Response({"message": "Logout successful!"})


class RegisterApiView(APIView):

    permission_classes = (AllowAny,)

    class InputSerializer(serializers.ModelSerializer):
        class Meta:
            model = get_user_model()
            fields = ['username', 'password']

    class OutputSerializer(serializers.Serializer):
        ROLE_CHOICES = [ROLE_ADMIN, ROLE_USER, ROLE_MODERATOR]

        id = serializers.IntegerField()
        username = serializers.CharField(max_length=255)
        first_name = serializers.CharField(allow_blank=True, allow_null=True)
        last_name = serializers.CharField(allow_blank=True, allow_null=True)
        role = serializers.ChoiceField(choices=ROLE_CHOICES)
        created_at = serializers.DateTimeField()

    def post(self, request, *args, **kwargs):

        serializer = self.InputSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            print(serializer.validated_data)
            hashed_password = make_password(serializer.validated_data.get("password"))
            print("hashed_password:", hashed_password)

            serializer.validated_data["password"] = hashed_password
            user = serializer.save()

        return Response(self.OutputSerializer(user).data)


class MeApiView(APIView):

    class OutputSerializer(serializers.Serializer):
        ROLE_CHOICES = [ROLE_ADMIN, ROLE_USER, ROLE_MODERATOR]

        id = serializers.IntegerField()
        username = serializers.CharField(max_length=255)
        first_name = serializers.CharField(allow_blank=True, allow_null=True)
        last_name = serializers.CharField(allow_blank=True, allow_null=True)
        role = serializers.ChoiceField(choices=ROLE_CHOICES)
        created_at = serializers.DateTimeField()

    def get(self, request, *args, **kwargs):
        return Response(self.OutputSerializer(request.user).data)