from app.api.auth import get_current_user
from app.config import settings
from app.core.security import PermissionChecker
from fastapi import APIRouter
from fastapi import Depends

router = APIRouter(tags=["Test Resources"])


@router.get(f"{settings.API_V1_STR}/resources/public")
def get_public_resource() -> dict[str, str]:
    """
    Возвращает общедоступный ресурс.
    Не требует аутентификации или специальных прав.

    Returns:
        Dict[str, str]: Сообщение о доступности ресурса.
    """
    return {"message": "This is a public resource. Everyone can see this!"}


@router.get(
    f"{settings.API_V1_STR}/resources/user",
    dependencies=[Depends(get_current_user), Depends(PermissionChecker(["view_user_resource"]))],
)
def get_user_resource() -> dict[str, str]:
    """
    Возвращает ресурс, доступный для обычных пользователей.
    Требует права: 'view_user_resource'.

    Returns:
        Dict[str, str]: Сообщение о доступности ресурса.
    """
    return {"message": "This is a protected resource for regular users."}


@router.get(
    f"{settings.API_V1_STR}/resources/admin",
    dependencies=[Depends(get_current_user), Depends(PermissionChecker(["view_admin_resource"]))],
)
def get_admin_resource() -> dict[str, str]:
    """
    Возвращает ресурс, доступный только для администраторов.
    Требует права: 'view_admin_resource'.

    Returns:
        Dict[str, str]: Сообщение о доступности ресурса.
    """
    return {"message": "This is a super secret resource for admins only!"}
