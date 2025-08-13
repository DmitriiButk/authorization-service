from datetime import datetime, timedelta
from typing import Optional, Union, Any
from fastapi.security import OAuth2PasswordBearer

import jwt
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет, соответствует ли открытый пароль хэшированному паролю.

    Args:
        plain_password (str): Открытый пароль для проверки
        hashed_password (str): Хэшированный пароль для сравнения

    Returns:
        bool: True, если пароль верный, иначе False
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Создает хэш пароля.

    Args:
        password (str): Пароль для хэширования

    Returns:
        str: Хэшированный пароль
    """
    return pwd_context.hash(password)


def create_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Создает JWT токен с указанным сроком действия.

    Args:
        subject (Union[str, Any]): Субъект токена (обычно ID пользователя)
        expires_delta (Optional[timedelta]): Срок действия токена

    Returns:
        str: Закодированный JWT токен
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_access_token(subject: Union[str, Any]) -> str:
    """
    Создает access токен с установленным сроком действия.

    Args:
        subject (Union[str, Any]): Субъект токена (обычно ID пользователя)

    Returns:
        str: Закодированный JWT access токен
    """
    return create_token(
        subject,
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )


def create_refresh_token(subject: Union[str, Any]) -> str:
    """
    Создает refresh токен с установленным сроком действия.

    Args:
        subject (Union[str, Any]): Субъект токена (обычно ID пользователя)

    Returns:
        str: Закодированный JWT refresh токен
    """
    return create_token(
        subject,
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
