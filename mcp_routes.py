# mcp_routes.py
from flask import Blueprint, request, jsonify, Response
import json
import queue
import threading
import time

# Création d'un "Blueprint" Flask (module réutilisable)
mcp_bp = Blueprint('mcp', __name__, url_prefix='/mcp')

# Stockage des sessions SSE (une queue par client connecté)
sse_clients = {}

@mcp_bp.route('/sse', methods=['GET'])
def sse_endpoint():
    """Endpoint SSE pour les clients MCP (Claude, Cursor, etc.)"""
    client_id = request.args.get('client_id', f"client_{int(time.time())}")
    client_queue = queue.Queue()
    sse_clients[client_id] = client_queue
    
    def generate():
        try:
            # Envoi initial : message de bienvenue MCP
            welcome = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }
            yield f"data: {json.dumps(welcome)}\n\n"
            
            # Boucle infinie pour garder la connexion SSE ouverte
            while True:
                try:
                    message = client_queue.get(timeout=30)
                    yield f"data: {json.dumps(message)}\n\n"
                except queue.Empty:
                    # Heartbeat pour éviter la déconnexion
                    yield ": heartbeat\n\n"
        finally:
            if client_id in sse_clients:
                del sse_clients[client_id]
    
    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'  # Important pour Render/Nginx
    })

@mcp_bp.route('/messages', methods=['POST'])
def messages_endpoint():
    """Reçoit les requêtes JSON-RPC des clients MCP"""
    data = request.json
    client_id = request.args.get('client_id') or data.get('params', {}).get('client_id')
    
    # Traitement des méthodes MCP standards
    method = data.get('method', '')
    request_id = data.get('id')
    
    response = {"jsonrpc": "2.0", "id": request_id}
    
    if method == 'initialize':
        response['result'] = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "CerbereAG", "version": "1.0.0"}
        }
    elif method == 'tools/list':
        response['result'] = {
            "tools": [
                {
                    "name": "check_prompt_security",
                    "description": "Vérifie si un prompt contient des injections ou des fuites de PII",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string", "description": "Le texte à analyser"}
                        },
                        "required": ["text"]
                    }
                },
                {
                    "name": "get_agent_metrics",
                    "description": "Récupère les métriques de sécurité et d'observabilité d'un agent",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "agent_id": {"type": "string", "description": "ID de l'agent"}
                        },
                        "required": ["agent_id"]
                    }
                }
            ]
        }
    elif method == 'tools/call':
        tool_name = data['params']['name']
        arguments = data['params'].get('arguments', {})
        
        # Ici, tu appelles TA logique métier existante
        if tool_name == 'check_prompt_security':
            # Exemple : utilise ton PolicyEngine existant
            from agentguard.policy import PolicyEngine
            engine = PolicyEngine()
            result = engine.check_injection(arguments.get('text', ''))
            response['result'] = {
                "content": [{"type": "text", "text": json.dumps({
                    "passed": result.passed,
                    "risk_level": result.risk_level.value,
                    "details": result.details
                })}]
            }
        elif tool_name == 'get_agent_metrics':
            # Exemple : appelle ton backend existant
            response['result'] = {
                "content": [{"type": "text", "text": json.dumps({
                    "agent_id": arguments.get('agent_id'),
                    "status": "active",
                    "blocked_attempts": 42
                })}]
            }
    else:
        response['error'] = {"code": -32601, "message": f"Method not found: {method}"}
    
    # Envoie la réponse via SSE au client concerné
    if client_id and client_id in sse_clients:
        sse_clients[client_id].put(response)
    
    return jsonify({"status": "ok"})

@mcp_bp.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "cerbereag-mcp"})
