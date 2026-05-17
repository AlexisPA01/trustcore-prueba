from fastapi.testclient import TestClient
from app.main import app
from app.database import db

client = TestClient(app)

def test_get_vulnerabilities_success():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.get(
        "/v1/vulnerabilities",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "message" in data
    assert "total" in data
    assert "vulnerabilities" in data

def test_get_vulnerabilities_invalid():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.get(
        "/v1/vulnerabilities",
        params={
            "pubStartDate": "2025-01-A",
            "pubEndDate": "asas"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 500

    data = response.json()

    assert "success" in data
    assert "message" in data
    assert "error" in data
    assert "total" in data
    assert "vulnerabilities" in data

def test_get_vulnerabilities_invalid_params():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.get(
        "/v1/vulnerabilities",
        params={
            "resultsPerPage": "abc"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 422

def test_create_vulnerabilities_success():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.post(
        "/v1/fixed",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json=[
            {
                "cve": {
                    "id": "CVE-1999-0082",
                    "sourceIdentifier": "cve@mitre.org",
                    "vulnStatus": "Modified"
                }
            },
            {
                "cve": {
                "id": "CVE-1999-1471",
                "sourceIdentifier": "cve@mitre.org",
                "vulnStatus": "Modified"
                }
            }
        ]
    )

    assert response.status_code == 200

    data = response.json()

    assert "message" in data
    assert "total" in data
    assert "inserted_ids" in data

def test_create_vulnerabilities_invalid():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.post(
        "/v1/fixed",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json=[{
            "cve": {
                "test":"asasa"
            }
        }]
    )

    assert response.status_code == 500

    data = response.json()

    assert "success" in data
    assert "message" in data
    assert "error" in data
    assert "total" in data
    assert "inserted_ids" in data

def test_create_vulnerabilities_invalid_params():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.post(
        "/v1/fixed",
        data={
            "resultsPerPage": "abc"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 422

def test_get_vulnerabilities_active_success():
    db.vulnerabilities.delete_many({"cve.test": "asasa"})

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

    assert response.status_code == 200

    data = response.json()

    assert "message" in data
    assert "total" in data
    assert "vulnerabilities" in data

def test_get_summary_vulnerabilities_success():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.get(
        "/v1/vulnerabilities/summary",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "message" in data
    assert "total" in data
    assert "summary" in data

def test_delete_vulnerabilities_success():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.request(
        "DELETE",
        "/v1/unfixed",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json=[{
            "cve": {
                "id": "CVE-1999-0082",
            }
        }]
    )

    assert response.status_code == 200

    data = response.json()

    assert "message" in data
    assert "total" in data
    assert "deleted_ids" in data

def test_delete_vulnerabilities_invalid():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.request(
        "DELETE",
        "/v1/unfixed",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json=[{
            "cve": {
                "test":"asasa"
            }
        }]
    )

    assert response.status_code == 500

    data = response.json()

    assert "success" in data
    assert "message" in data
    assert "error" in data
    assert "total" in data
    assert "deleted_ids" in data

def test_delete_vulnerabilities_invalid_params():
    login = client.post(
        "/login",
        data={
            "username": "johndoe",
            "password": "123456"
        }
    )

    token = login.json()["access_token"]

    response = client.request(
        "DELETE",
        "/v1/unfixed",
        data={
            "resultsPerPage": "abc"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 422