from datetime import datetime
from datetime import timedelta
from typing import Any

import jwt
from app.config import settings
from app.database.models.user import User as UserModel
from fastapi import Depends
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from starlette import status

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


class PermissionChecker:
    """
    Класс-зависимость для проверки прав доступа пользователя.

    Проверяет, обладает ли аутентифицированный пользователь всеми необходимыми
    разрешениями для доступа к эндпоинту.

    Args:
        required_permissions (list[str]): Список названий разрешений, которые требуются.
    """

    def __init__(self, required_permissions: list[str]):
        self.required_permissions = required_permissions

    def __call__(self, user: UserModel = Depends()):
        """
        Вызывается FastAPI при обработке зависимости.

        Args:
            user (UserModel): Текущий пользователь, полученный из зависимости [get_current_user](cci:1://file:///C:/Users/Dmitrii/PycharmProjects/authorization-service/app/api/auth.py:9:0-31:93),
                            которая должна быть передана в эндпоинт.

        Returns:
            UserModel: Тот же объект пользователя, если проверка пройдена.

        Raises:
            HTTPException: Если у пользователя нет необходимых прав (403 Forbidden).
        """
        user_permissions = set()
        for role in user.roles:
            for permission in role.permissions:
                user_permissions.add(permission.name)

        if not set(self.required_permissions).issubset(user_permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to perform this action"
            )
        return user


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


def create_token(subject: str | Any, expires_delta: timedelta | None = None) -> str:
    """
    Создает JWT токен с указанным субъектом и сроком действия.

    Args:
        subject (Union[str, Any]): Субъект токена (обычно ID пользователя).
        expires_delta (Optional[timedelta]): Срок действия токена. Если не указан,
                                               используется значение по умолчанию.

    Returns:
        str: Закодированный JWT токен.
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_access_token(subject: str | Any) -> str:
    """
    Создает access токен с коротким сроком действия.

    Args:
        subject (Union[str, Any]): Субъект токена (ID пользователя).

    Returns:
        str: Закодированный JWT access токен.
    """
    return create_token(subject, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(subject: str | Any) -> str:
    """
    Создает refresh токен с длительным сроком действия.

    Args:
        subject (Union[str, Any]): Субъект токена (ID пользователя).

    Returns:
        str: Закодированный JWT refresh токен.
    """
    return create_token(subject, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
