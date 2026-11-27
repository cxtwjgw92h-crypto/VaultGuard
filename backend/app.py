"""
VaultGuard Flask Application Entry Point

Initializes the Flask app, SQLAlchemy database, CORS, security headers,
API blueprints, and safe error handlers.
"""

import os
from flask import Flask, jsonify
from flask_cors import CORS

from config import Config
from models import db
from routes.alerts import alerts_bp
from routes.assistant import assistant_bp
from routes.auth import auth_bp
from routes.credentials import credentials_bp
from routes.monitoring import monitoring_bp
from routes.risk import risk_bp


def create_app(config_class=Config) -> Flask:
    """Application factory creating a configured Flask instance."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable CORS for the React frontend
    CORS(
        app,
        resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}},
        supports_credentials=True,
    )

    # Initialize database ORM
    db.init_app(app)

    # Register modular API blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(credentials_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(assistant_bp)

    @app.after_request
    def apply_security_headers(response):
        """Attach baseline HTTP security headers to every API response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Simple health check endpoint."""
        return jsonify({"status": "ok", "service": "VaultGuard API"}), 200

    @app.errorhandler(404)
    def not_found(_err):
        return jsonify({"error": "Requested resource not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_err):
        return jsonify({"error": "HTTP method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(_err):
        # Never expose internal stack traces to clients
        return jsonify({"error": "An internal server error occurred."}), 500

    # Create tables if they do not exist yet
    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    application = create_app()
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    application.run(host="127.0.0.1", port=port, debug=debug)
