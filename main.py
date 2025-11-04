from contextlib import asynccontextmanager

from app.api.admin import router as admin_router
from app.api.auth import router as auth_router
from app.api.mock_resources import router as resources_router
from app.config import settings
from app.database.database import Base
from app.database.database import SessionLocal
from app.database.database import engine
from app.database.init_db import init_db
from app.database.models.rbac import Permission  # noqa
from app.database.models.rbac import Role  # noqa
from app.database.models.user import User  # noqa
from fastapi import FastAPI


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("Starting up...")
    db = SessionLocal()
    try:
        init_db(db)
    finally:
        db.close()
    yield
    print("Shutting down...")


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)
app.include_router(auth_router)
app.include_router(resources_router)
app.include_router(admin_router)
