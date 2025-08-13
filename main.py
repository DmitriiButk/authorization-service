from fastapi import FastAPI
from contextlib import asynccontextmanager

from app.config import settings
from app.database.database import Base, engine
from app.api.auth import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("Starting up...")
    yield
    print("Shutting down...")


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)
app.include_router(router)
