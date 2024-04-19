#!/usr/bin/env python3
''' Module for Session Authentication views '''
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def auth_session_login() -> str:
    ''' POST /api/v1/auth_session/login
    Return:
      - User object JSON represented
    '''
    email = request.form.get('email')
    password = request.form.get('password')
    if email is None or password is None:
        return jsonify({"error": "email or password missing"}), 400
    user = User.search({'email': email})
    if user is None or not user.is_valid_password(password):
        return jsonify({"error": "no user found for this email/password"}), 404
    from api.v1.app import auth
    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    response.set_cookie('session_id', session_id)
    return response


@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def auth_session_logout() -> str:
    ''' DELETE /api/v1/auth_session/logout
    Return:
      - empty JSON
    '''
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(403)
    return jsonify({}), 200
