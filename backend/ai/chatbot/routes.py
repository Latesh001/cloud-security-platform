from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from ai.chatbot.service import ChatbotService

chatbot_bp = Blueprint("chatbot", __name__, url_prefix="/api/chatbot")

VALID_TABS = {"project", "security", "soc", "viva"}


@chatbot_bp.route("/ask", methods=["POST"])
@jwt_required()
def ask():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    question = (data.get("question") or "").strip()
    project_id = data.get("project_id") or None
    tab = data.get("tab", "security")

    if not question:
        return jsonify({"error": "Question is required"}), 400
    if len(question) > 8000:
        return jsonify({"error": "Question is too long (8000 character limit)"}), 400
    if tab not in VALID_TABS:
        tab = "security"

    return jsonify(ChatbotService.answer(user_id, question, project_id, tab)), 200


@chatbot_bp.route("/suggestions", methods=["GET"])
@jwt_required()
def suggestions():
    tab = request.args.get("tab", "security")
    if tab not in VALID_TABS:
        tab = "security"
    return jsonify({"tab": tab, "suggestions": ChatbotService.get_suggested_questions(tab)}), 200


@chatbot_bp.route("/history", methods=["GET"])
@jwt_required()
def history():
    user_id = int(get_jwt_identity())
    return jsonify({"history": ChatbotService.get_history(user_id)}), 200


@chatbot_bp.route("/history", methods=["DELETE"])
@jwt_required()
def clear_history():
    user_id = int(get_jwt_identity())
    deleted = ChatbotService.clear_history(user_id)
    return jsonify({"message": "Conversation cleared", "deleted": deleted}), 200
