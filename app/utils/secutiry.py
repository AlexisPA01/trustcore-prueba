from http import client
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

router = APIRouter()

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

fake_users_db = {
    "username": "johndoe",
    "password": "123456"
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(minutes=60)

    to_encode.update({
        "exp": expire
    })

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

@router.post(
        "/login",
        tags=["Auth"],
        )
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if (
        form_data.username != fake_users_db["username"] or
        form_data.password != fake_users_db["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Credenciales incorrectas"
        )

    access_token = create_access_token({
       "sub": form_data.username
    })

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if username is None:
            raise HTTPException(
                status_code=401,
                detail="Token inválido"
            )

        return username

    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Token inválido"
        )
