from fastapi.testclient import TestClient
from app.main import app
import jwt

client = TestClient(app)

def test_login_success():

    response = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid():

    response = client.post(
        "/login",
        data={
            "username": "bad",
            "password": "bad"
        }
    )

    assert response.status_code == 401

def test_invalid_token():

    response = client.get(
        "/v1/vulnerabilities/active",
        headers={
            "Authorization": "Bearer invalid_token"
        }
    )

    assert response.status_code == 401

def test_invalid_username_token():
    token = jwt.encode(
        {"test": "value"},
        "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
        algorithm="HS256"
    )

    response = client.get(
        "/v1/vulnerabilities/active",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 401

def test_valid_token():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.get(
        "/v1/vulnerabilities/active",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code != 401