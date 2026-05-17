# Trustcore Vulnerability API

API REST desarrollada con FastAPI para consultar vulnerabilidades desde la NVD API, registrar vulnerabilidades 'fixeadas', obtener información resumida de severidad y eliminar registros 'fixeados'.

## Tecnologías

- Python
- FastAPI
- MongoDB
- JWT Authentication
- Pytest
- Docker

## Requisitos

- Python 3.10+
- MongoDB
- Docker

## Instalación

Clonar el repositorio:

```bash
git clone https://github.com/AlexisPA01/trustcore-prueba.git
cd trustcore-prueba
```

Crear entorno virtual:

```bash
python3 -m venv venv
```

Activar entorno virtual:

Linux/macOS:

```bash
source venv/bin/activate
```

Instalar dependencias:

```bash
pip install -r requirements.txt
```

## Variables de entorno

Crear un archivo `.env` en la raíz del proyecto y copiar las variables de entorno que se compartieron en la entrega de la prueba:

```env
MONGO_URL=<url>
DATABASE_NAME=<nombre_db>
```

## Ejecución sin Docker

Iniciar servidor:

```bash
uvicorn app.main:app --reload
```

La API esta disponible en:

```text
http://localhost:8000
```

Swagger UI:

```text
http://localhost:8000/docs
```

## Autenticación

La API utiliza JWT Bearer Token, para efectos practicos no se creo un usuario y contraseña real, en su lugar se utilizaron credenciales falsas para simular un usuario y que este creé el 'token' y simule la 'autentificación' 

### Login

Al utilizar el login se genera el 'bearer token' para utilizarlo en las peticiones

Respuesta:

```json
{
  "access_token": "TOKEN",
  "token_type": "bearer"
}
```


---

## Ejemplos curl

---

# Obtener vulnerabilidades

```bash
GET "/v1/vulnerabilities" \ 
"Authorization: Bearer TOKEN"
```

# Registrar vulnerabilidades

```bash
POST "/v1/fixed" \
"Authorization: Bearer TOKEN" \
body '[
  {
    "cve": {
      "id": "CVE-1999-0082"
    }
  }
]'
```

### Eliminar vulnerabilidades fixeadas

```bash
DELETE "/v1/unfixed" \
"Authorization: Bearer TOKEN" \
body '[
  {
    "cve": {
      "id": "CVE-1999-0082"
    }
  }
]'
```

## Testing

Ejecutar tests:

```bash
pytest
```

Ejecutar test con covertura:

```bash
pytest --cov=app --cov-report=term-missing
```

## Docker

Construir y ejecutar:

```bash
docker-compose up --build