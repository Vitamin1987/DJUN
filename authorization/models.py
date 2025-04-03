from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import make_password
from django.db import models
from django.contrib.auth.models import User, AbstractUser, PermissionsMixin
from authorization.constants import ROLE_USER, ROLE_ADMIN, ROLE_MODERATOR



class UserManager(BaseUserManager):
    def create_user(self, username, email=None, password=None, **extra_fields):
        if email:
            email = self.normalize_email(email)

        user = self.model(username=username, email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):

    ROLES_CHOICES = [
        ('ROLE_ADMIN', 'Админ'),
        ('ROLE_USER', 'Юзер'),
        ('ROLE_MODERATOR', 'Модератор'),
    ]

    username = models.CharField(max_length=255, unique=True)

    email = models.EmailField(
        max_length=255,
        unique=True,
        blank=True,
        null=True
    )

    is_active = models.BooleanField(default=True, db_index=True)
    is_staff = models.BooleanField(default=False, db_index=True)

    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)

    role = models.CharField(
        max_length=50,
        choices=ROLES_CHOICES,
        default='ROLE_USER',
    )

    created_at = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "username"

# Create your models here.
