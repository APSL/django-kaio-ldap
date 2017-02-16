# -*- coding: utf-8 -*-
from django_auth_ldap.backend import LDAPBackend as _LDAPBackend

from django.contrib.auth.backends import ModelBackend


class LDAPBackend(_LDAPBackend):
    """
    The main backend class. Although it actually delegates most of its work to
    django-auth-ldap implementation.
    """

    @staticmethod
    def staff_authentication(username, password, **kwargs):
        user = ModelBackend().authenticate(username, password, **kwargs)
        if user and (user.is_staff or user.is_superuser):
            return user

    def user_exists(self, username):
        model = self.get_user_model()
        username_field = getattr(model, 'USERNAME_FIELD', 'username')
        return model.objects.filter(**{username_field + '__iexact': username, 'is_active': True}).exists()

    def authenticate(self, username, password, **kwargs):
        """
        Authenticate against the BIMA system and
        :param username:
        :param password:
        :param kwargs:
        :return:
        """
        # authenticate with superuser or staff permissions
        staff = self.staff_authentication(username, password, **kwargs)
        if staff is not None:
            return staff
        # if is not superuser or staff is needed authenticate through LDAP
        return super().authenticate(username, password, **kwargs)

    def has_perm(self, user, perm, obj=None):
        # check perms with django auth backend
        return False

    def has_module_perms(self, user, app_label):
        # check perms with django auth backend
        return False

    def get_all_permissions(self, user, obj=None):
        # check perms with django auth backend
        return ()

    def get_group_permissions(self, user, obj=None):
        # check perms with django auth backend
        return ()