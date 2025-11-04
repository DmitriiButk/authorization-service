import jwt
from app.config import settings
from app.core.security import create_access_token
from app.core.security import create_refresh_token
from app.core.security import get_password_hash
from app.core.security import oauth2_scheme
from app.core.security import verify_password
from app.database.database import get_db
from app.database.models.rbac import Role
from app.database.models.user import User as UserModel
from app.schemas.token import Token
from app.schemas.user import User
from app.schemas.user import UserCreate
from app.schemas.user import UserUpdate
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette import status

router = APIRouter(tags=["User"])


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> UserModel:
    """
    Получает текущего аутентифицированного пользователя по JWT токену.

    Args:
        db (Session): Сессия базы данных.
        token (str): JWT токен доступа, извлеченный из заголовка Authorization.

    Returns:
        UserModel: Объект пользователя SQLAlchemy.

    Raises:
        HTTPException: Если токен недействителен, или пользователь не найден.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY.get_secret_value(), algorithms=[settings.JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.post(f"{settings.API_V1_STR}/auth/register", response_model=User)
def register(*, db: Session = Depends(get_db), user_in: UserCreate) -> User:
    """
    Регистрация нового пользователя.
    При регистрации пользователю автоматически присваивается роль 'user'.

    Args:
        db (Session): Сессия базы данных.
        user_in (UserCreate): Данные нового пользователя.

    Returns:
        User: Созданный пользователь.

    Raises:
        HTTPException: Если email уже занят или роль 'user' не найдена.
    """
    user = db.query(UserModel).filter(UserModel.email == user_in.email).first()
    if user:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        raise HTTPException(status_code=500, detail="Default user role not found.")

    hashed_password = get_password_hash(user_in.password)
    user = UserModel(
        email=user_in.email, hashed_password=hashed_password, full_name=user_in.full_name, roles=[user_role]
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post(f"{settings.API_V1_STR}/auth/login", response_model=Token)
def login(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    """
    Аутентификация пользователя и выдача пары токенов (access и refresh).

    Args:
        db (Session): Сессия базы данных.
        form_data (OAuth2PasswordRequestForm): Форма с 'username' (email) и 'password'.

    Returns:
        Token: Объект с access_token и refresh_token.

    Raises:
        HTTPException: Если учетные данные неверны или пользователь неактивен.
    """
    user = db.query(UserModel).filter(UserModel.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    return Token(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.get(f"{settings.API_V1_STR}/users/me", response_model=User)
def get_current_user_info(current_user: UserModel = Depends(get_current_user)) -> User:
    """
    Получение информации о текущем аутентифицированном пользователе.

    Args:
        current_user (UserModel): Зависимость, получающая текущего пользователя.

    Returns:
        User: Pydantic-модель с информацией о пользователе.
    """
    return current_user


@router.patch(f"{settings.API_V1_STR}/users/me", response_model=User)
def update_current_user_info(
    *, db: Session = Depends(get_db), user_in: UserUpdate, current_user: UserModel = Depends(get_current_user)
) -> User:
    """
    Обновление информации о текущем пользователе (имя, email, пароль).

    Args:
        db (Session): Сессия базы данных.
        user_in (UserUpdate): Данные для обновления.
        current_user (UserModel): Текущий аутентифицированный пользователь.

    Returns:
        User: Обновленная информация о пользователе.

    Raises:
        HTTPException: Если новый email уже занят.
    """
    if user_in.full_name is not None:
        current_user.full_name = user_in.full_name

    if user_in.password is not None:
        current_user.hashed_password = get_password_hash(user_in.password)

    if user_in.email is not None and user_in.email != current_user.email:
        existing_user = db.query(UserModel).filter(UserModel.email == user_in.email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        current_user.email = user_in.email

    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user


@router.delete(f"{settings.API_V1_STR}/users/me", status_code=status.HTTP_204_NO_CONTENT)
def soft_delete_current_user(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    """
    Мягкое удаление текущего пользователя (устанавливает is_active = False).

    Args:
        db (Session): Сессия базы данных.
        current_user (UserModel): Текущий аутентифицированный пользователь.
    """
    current_user.is_active = False
    db.add(current_user)
    db.commit()
    return


@router.post(f"{settings.API_V1_STR}/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout():
    """
    Выход из системы.
    На стороне клиента это означает удаление токенов.
    """
    return
