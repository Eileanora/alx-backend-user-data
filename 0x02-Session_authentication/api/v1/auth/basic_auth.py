#!/usr/bin/env python3
''' Module for Basic Authentication '''
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    ''' Basic Auth class '''
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        ''' Method that returns the Base64 part of the Authorization header '''
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        ''' Method that returns the decoded value of a Base64 string '''
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            return base64.b64decode(
                base64_authorization_header.encode('utf-8')).decode('utf-8')
        except BaseException:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_header: str) -> (str, str):
        ''' Method for extracting user credentials from header '''
        if decoded_base64_header is None:
            return None, None
        if type(decoded_base64_header) is not str:
            return None, None
        if ':' not in decoded_base64_header:
            return None, None
        return tuple(decoded_base64_header.split(':', 1))

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        ''' Method that returns the User instance \
            based on his email and password '''
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        if len(users) == 0:
            return None
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        ''' Method that overloads Auth and retrieves \
            the User instance for a request '''
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        base64_header = self.extract_base64_authorization_header(auth_header)
        if base64_header is None:
            return None
        decoded_base64_auth_header = self.decode_base64_authorization_header(
            base64_header)
        user_credentials = self.extract_user_credentials(
            decoded_base64_auth_header)
        if user_credentials is None:
            return None
        user = self.user_object_from_credentials(
            user_credentials[0], user_credentials[1])
        return user
