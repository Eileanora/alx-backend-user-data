#!/usr/bin/env python3
''' Module for Basic Authentication '''
from api.v1.auth.auth import Auth
import base64


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
