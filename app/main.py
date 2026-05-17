from fastapi import FastAPI, Depends
from app.routes.request import router as request_router
from app.utils.secutiry import router as auth
from app.utils.secutiry import verify_token

app = FastAPI(
    title="Trustcore prueba técnica Alexis Patiño",
    description=f"""Esta es la documentación para la API que se pidio para la prueba 
    que permita obtener un listado de vulnerabilidades del NIST
        """
)

app.include_router(auth)

app.include_router(
    request_router,
    dependencies=[Depends(verify_token)]
)