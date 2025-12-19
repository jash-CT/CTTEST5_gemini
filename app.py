import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, request
from flask_wtf import CSRFProtect
from flask_talisman import Talisman

from config import config
from models import db, Loan, LoanStatusEnum, User
from auth import auth_bp, login_manager, record_audit
from schemas import LoanApplyIn, LoanReviewIn, validate_request


def create_app(config_name="default", testing: bool = False):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    # Allow tests to disable some protections for easier programmatic testing
    app.config["TESTING"] = testing

    # Initialize extensions
    db.init_app(app)

    login_manager.init_app(app)

    # Initialize CSRF only when not testing to simplify automated tests. In
    # production/testing pipelines, prefer enabling CSRF and using proper token
    # exchange for API clients.
    csrf = CSRFProtect()
    if not app.config.get("TESTING", False):
        csrf.init_app(app)

    # Talisman for CSP/HSTS
    talisman = Talisman(app, content_security_policy=app.config.get("CONTENT_SECURITY_POLICY"))

    # Register blueprints
    app.register_blueprint(auth_bp)

    # Logging
    handler = RotatingFileHandler(app.config.get("LOG_FILE"), maxBytes=10 * 1024 * 1024, backupCount=5)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)


    # Loans blueprint inline to keep deliverable compact
    from flask import Blueprint
    from flask_login import current_user, login_required
    from models import Loan, AuditLog

    loans_bp = Blueprint("loans", __name__, url_prefix="/loans")


    @loans_bp.route("/apply", methods=["POST"])
    @login_required
    def apply_loan():
        # Only customers should apply
        if current_user.role.name.lower() != "customer":
            return jsonify({"error": "Forbidden"}), 403

        data = request.get_json(silent=True) or {}
        payload, err = validate_request(LoanApplyIn, data)
        if err:
            return jsonify({"error": "Invalid input"}), 400

        loan = Loan(
            applicant_id=current_user.id,
            amount=payload.amount,
            purpose=payload.purpose,
            term_months=payload.term_months,
        )
        db.session.add(loan)
        db.session.commit()

        # Audit
        record_audit(current_user.id, "create_loan", resource="loan", resource_id=loan.id, ip=request.remote_addr)

        return jsonify({"message": "loan_created", "loan_id": loan.id}), 201


    @loans_bp.route("/my-applications", methods=["GET"])
    @login_required
    def my_applications():
        # Customers can see only their loans; officers could optionally see all (restricted here)
        loans = Loan.query.filter_by(applicant_id=current_user.id).all()
        out = [
            {
                "id": l.id,
                "amount": l.amount,
                "purpose": l.purpose,
                "term_months": l.term_months,
                "status": l.status.value,
                "created_at": l.created_at.isoformat(),
            }
            for l in loans
        ]
        return jsonify({"loans": out}), 200


    @loans_bp.route("/review/<int:loan_id>", methods=["PATCH"])
    def review_loan(loan_id):
        # Only officers allowed
        from auth import role_required

        @role_required("officer")
        def _inner(loan_id=loan_id):
            data = request.get_json(silent=True) or {}
            payload, err = validate_request(LoanReviewIn, data)
            if err:
                return jsonify({"error": "Invalid input"}), 400

            loan = Loan.query.get_or_404(loan_id)
            if loan.status != LoanStatusEnum.PENDING:
                return jsonify({"error": "Loan not pending"}), 400

            if payload.decision == "approve":
                loan.status = LoanStatusEnum.APPROVED
            else:
                loan.status = LoanStatusEnum.REJECTED

            db.session.add(loan)
            db.session.commit()

            # Audit record with officer user id
            record_audit(
                current_user.id,
                "review_loan",
                resource="loan",
                resource_id=loan.id,
                ip=request.remote_addr,
                detail=payload.comment,
            )

            return jsonify({"message": "loan_reviewed", "status": loan.status.value}), 200

        return _inner()


    app.register_blueprint(loans_bp)


    # Error handlers - do not leak PII
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request"}), 400


    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "Unauthorized"}), 401


    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "Forbidden"}), 403


    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404


    @app.errorhandler(500)
    def internal_error(e):
        # Log exception details server-side but return generic message
        app.logger.exception("Internal server error")
        return jsonify({"error": "Internal server error"}), 500


    # Make a small helper to create DB tables during dev
    @app.cli.command("init-db")
    def init_db():
        with app.app_context():
            db.create_all()
            print("Database initialized")

    return app


if __name__ == "__main__":
    app = create_app("default")
    app.run(host="0.0.0.0", port=5000)
