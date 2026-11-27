"""
AI Security Assistant Routes (Module 6)

Answers user security questions and provides automated posture briefings
using structured, sanitized security event metadata.
"""

from flask import Blueprint, g, jsonify, request

from services.ai_assistant import ask_security_assistant
from services.auth_utils import token_required

assistant_bp = Blueprint("assistant", __name__, url_prefix="/api/assistant")


@assistant_bp.route("/ask", methods=["POST"])
@token_required
def ask_assistant():
    """Respond to a user security question grounded in real backend events."""
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "Please enter a question for the AI Security Assistant."}), 400
    if len(question) > 1000:
        return jsonify({"error": "Question is too long (maximum 1000 characters)."}), 400

    reply = ask_security_assistant(g.current_user.id, question)
    return jsonify(reply), 200


@assistant_bp.route("/summary", methods=["GET"])
@token_required
def get_security_summary():
    """Generate an immediate security posture summary for the authenticated user."""
    reply = ask_security_assistant(g.current_user.id, "Summarize my recent security activity and status.")
    return jsonify(reply), 200
