from fastapi import FastAPI
from pets.routes import pets_router
from users.routes import user_router
from config import config

app = FastAPI()


app.include_router(
    pets_router,
    prefix="/pets",
    tags=["pets"],
    responses={404: {"description": "Not found"}},
)

app.include_router(
    user_router,
    prefix="/auth",
    tags=["auth"],
    responses={404: {"description": "Not found"}},
)


@app.on_event("startup")
async def app_startup():
    """
    Do tasks related to app initialization.
    """
    # This if fact does nothing its just an example.
    config.load_config()


@app.on_event("shutdown")
async def app_shutdown():
    """
    Do tasks related to app termination.
    """
    # This does finish the DB driver connection.
    config.close_db_client()