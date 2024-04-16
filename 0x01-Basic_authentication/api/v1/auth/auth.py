#!/usr/bin/env python3
''' Module for managing API authentication '''
from flask import request
from typing import List, TypeVar

class Auth:
    ''' Auth class '''

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        ''' Function that checks if a path needs authentication '''
        return False

    def authorization_header(self, request=None) -> str:
        ''' Function that checks the authorization header '''
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        ''' Function that returns the current user '''
        return None
