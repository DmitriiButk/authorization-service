from fastapi import Depends, HTTPException, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from starlette import status
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import get_password_hash, verify_password, create_access_token, create_refresh_token
from app.database.crud import get_current_user
from app.database.database import get_db
from app.schemas.token import Token
from app.schemas.user import User, UserCreate
from app.database.models.user import User as UserModel

router = APIRouter()


@router.post(f"{settings.API_V1_STR}/auth/register", response_model=User)
def register(*, db: Session = Depends(get_db), user_in: UserCreate) -> User:
    """
    Регистрация нового пользователя.

    Args:
        db (Session): Сессия базы данных
        user_in (UserCreate): Данные для создания пользователя

    Returns:
        User: Созданный пользователь

    Raises:
        HTTPException: Если пользователь с таким email уже существует
    """
    user = db.query(UserModel).filter(UserModel.email == user_in.email).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="User with this email already exists"
        )

    hashed_password = get_password_hash(user_in.password)
    user = UserModel(
        email=user_in.email,
        hashed_password=hashed_password
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post(f"{settings.API_V1_STR}/auth/login", response_model=Token)
def login(
        db: Session = Depends(get_db),
        form_data: OAuth2PasswordRequestForm = Depends()
) -> Token:
    """
    Аутентификация пользователя и выдача токенов доступа.

    Args:
        db (Session): Сессия базы данных
        form_data (OAuth2PasswordRequestForm): Форма с данными для входа (username=email, password)

    Returns:
        Token: Токены доступа и обновления

    Raises:
        HTTPException: При неверных учетных данных или неактивном пользователе
    """
    user = db.query(UserModel).filter(UserModel.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    return Token(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.get(f"{settings.API_V1_STR}/users/me", response_model=User)
def get_current_user_info(current_user: UserModel = Depends(get_current_user)) -> User:
    """
    Получение информации о текущем аутентифицированном пользователе.

    Args:
        current_user (UserModel): Текущий аутентифицированный пользователь

    Returns:
        User: Информация о текущем пользователе
    """
    return current_user
