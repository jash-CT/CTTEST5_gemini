from flask import Blueprint, request, jsonify, current_app, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from models import db, User, RoleEnum, AuditLog
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from schemas import RegisterIn, LoginIn, validate_request

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

login_manager = LoginManager()


def init_password_hasher(app):
    cfg = app.config
    return PasswordHasher(time_cost=cfg.get("ARGON2_TIME_COST", 2),
                          memory_cost=cfg.get("ARGON2_MEMORY_COST", 102400),
                          parallelism=cfg.get("ARGON2_PARALLELISM", 8))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def record_audit(user_id, action, resource=None, resource_id=None, ip=None, detail=None):
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=resource_id,
        ip_address=ip,
        detail=detail,
        timestamp=datetime.utcnow(),
    )
    db.session.add(log)
    db.session.commit()


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    payload, err = validate_request(RegisterIn, data)
    if err:
        return jsonify({"error": "Invalid input"}), 400

    ph = current_app.config.get("_password_hasher")
    if ph is None:
        ph = init_password_hasher(current_app)
        current_app.config["_password_hasher"] = ph

    hashed = ph.hash(payload.password)
    user = User(username=payload.username, email=payload.email, password_hash=hashed)
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        # Do not leak whether username or email exists
        return jsonify({"error": "Registration failed"}), 400

    # Audit
    record_audit(user.id, "create_user", resource="user", resource_id=user.id, ip=request.remote_addr)

    return jsonify({"message": "registered"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    payload, err = validate_request(LoginIn, data)
    if err:
        return jsonify({"error": "Invalid input"}), 400

    user = User.query.filter_by(username=payload.username).first()
    if not user:
        # Generic response
        return jsonify({"error": "Invalid credentials"}), 401

    ph = current_app.config.get("_password_hasher")
    if ph is None:
        ph = init_password_hasher(current_app)
        current_app.config["_password_hasher"] = ph

    try:
        ph.verify(user.password_hash, payload.password)
    except VerifyMismatchError:
        return jsonify({"error": "Invalid credentials"}), 401

    # Successful login
    login_user(user)
    session.permanent = True

    record_audit(user.id, "login", ip=request.remote_addr)

    return jsonify({"message": "logged_in"}), 200


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    uid = current_user.get_id()
    logout_user()
    record_audit(uid, "logout", ip=request.remote_addr)
    return jsonify({"message": "logged_out"}), 200


def role_required(role_name):
    def decorator(f):
        from functools import wraps

        @wraps(f)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Unauthorized"}), 401
            if current_user.role.value != role_name:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)

        return wrapped

    return decorator
