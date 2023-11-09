#!/usr/bin/env python3
"""Module containing User views.
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/users', methods=['GET'], strict_slashes=False)
def view_all_users() -> str:
    """GET /api/v1/users
    Return:
      - List of all User objects in JSON format.
    """
    all_users = [user.to_json() for user in User.all()]
    return jsonify(all_users)


@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)
def view_one_user(user_id: str = None) -> str:
    """GET /api/v1/users/:id
    Path parameter:
      - User ID.
    Return:
      - User object in JSON format.
      - 404 if the User ID doesn't exist.
    """
    if user_id is None:
        abort(404)
    if user_id == 'me':
        if request.current_user is None:
            abort(404)
        else:
            return jsonify(request.current_user.to_json())
    user = User.get(user_id)
    if user is None:
        abort(404)
    return jsonify(user.to_json())


@app_views.route('/users/<user_id>', methods=['DELETE'], strict_slashes=False)
def delete_user(user_id: str = None) -> str:
    """DELETE /api/v1/users/:id
    Path parameter:
      - User ID.
    Return:
      - Empty JSON if the User has been correctly deleted.
      - 404 if the User ID doesn't exist.
    """
    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)
    user.remove()
    return jsonify({}), 200


@app_views.route('/users', methods=['POST'], strict_slashes=False)
def create_user() -> str:
    """POST /api/v1/users/
    JSON body:
      - email.
      - password.
      - last_name (optional).
      - first_name (optional).
    Return:
      - User object in JSON format.
      - 400 if can't create the new User.
    """
    rj = request.get_json()
    error_msg = None

    if not rj or not rj.get("email"):
        error_msg = "Wrong format or email missing"
    elif not rj.get("password"):
        error_msg = "Password missing"
    else:
        try:
            user = User(
                email=rj.get("email"),
                password=rj.get("password"),
                first_name=rj.get("first_name"),
                last_name=rj.get("last_name")
            )
            user.save()
            return jsonify(user.to_json()), 201
        except Exception as e:
            error_msg = "Can't create User: {}".format(e)

    return jsonify({'error': error_msg}), 400


@app_views.route('/users/<user_id>', methods=['PUT'], strict_slashes=False)
def update_user(user_id: str = None) -> str:
    """PUT /api/v1/users/:id
    Path parameter:
      - User ID.
    JSON body:
      - last_name (optional).
      - first_name (optional).
    Return:
      - User object in JSON format.
      - 404 if the User ID doesn't exist.
      - 400 if can't update the User.
    """
    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)

    rj = request.get_json()
    if not rj:
        return jsonify({'error': "Wrong format"}), 400

    user.first_name = rj.get('first_name', user.first_name)
    user.last_name = rj.get('last_name', user.last_name)
    user.save()
    return jsonify(user.to_json()), 200

