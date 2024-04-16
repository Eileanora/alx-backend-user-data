#!/usr/bin/env python3
''' Module for managing API authentication '''
from flask import request
from typing import List, TypeVar


class Auth:
    ''' Auth class '''

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        ''' Function that checks if a path needs authentication '''
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path += '/'
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        ''' Function that checks the authorization header '''
        if request is None:
            return None
        if request.headers.get('Authorization') is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        ''' Function that returns the current user '''
        return None
