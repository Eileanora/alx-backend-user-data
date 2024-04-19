#!/usr/bin/env python3
''' Module for Session Authentication class '''
from .auth import Auth
from uuid import uuid4
from models.user import User


class SessionAuth(Auth):
    ''' Session Authentication class '''
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        ''' Creates a Session ID for a user_id '''
        if user_id is None:
            return None
        if not isinstance(user_id, str):
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        ''' Returns a User ID based on a Session ID '''
        if session_id is None:
            return None
        if not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        ''' Returns a User instance based on a cookie value '''
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        ''' Deletes the user session / logout '''
        if request is None:
            return False
        if not self.session_cookie(request):
            return False
        session_id = self.session_cookie(request)
        if not self.user_id_for_session_id(session_id):
            return False
        del self.user_id_by_session_id[session_id]
        return True
