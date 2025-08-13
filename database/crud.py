from fastapi import Depends, HTTPException
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import get_db
from app.database.models.user import User as UserModel
from app.core.security import oauth2_scheme


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
                     ) -> UserModel:
    """
    Получает текущего пользователя по JWT токену.

    Args:
        db (Session): Сессия базы данных
        token (str): JWT токен доступа

    Returns:
        UserModel: Объект пользователя

    Raises:
        HTTPException:
            - 401 если токен недействителен или отсутствует
            - 404 если пользователь не найден
            - 400 если пользователь неактивен
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user
