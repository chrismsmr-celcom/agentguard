import os

os.environ["AGENTGUARD_FLASK_SECRET"] = "test-secret"
os.environ["AGENTGUARD_DB_TYPE"] = "sqlite"
os.environ["AGENTGUARD_API_KEY"] = "test-api-key"

from collector import app


def test_healthz():
    app.config["TESTING"] = True
    with app.test_client() as c:
        assert c.get("/healthz").status_code in (200, 503)


def test_query_key_is_not_auth():
    app.config["TESTING"] = True
    with app.test_client() as c:
        r = c.get("/api/metrics?key=test-api-key")
        assert r.status_code == 401


def test_sdk_decorator_api():
    from agentguard_sdk import AgentGuard
    guard = AgentGuard(collector_url="http://127.0.0.1:9", debug=False)

    @guard.guard_tool_call("echo")
    def echo(message):
        return message

    assert echo(message="ok") == "ok"
