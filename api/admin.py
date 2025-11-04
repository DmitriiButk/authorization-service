from app.api.auth import get_current_user
from app.config import settings
from app.core.security import PermissionChecker
from app.database.database import get_db
from app.database.models.rbac import Permission
from app.database.models.rbac import Role
from app.database.models.user import User
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from sqlalchemy.orm import Session
from starlette import status

router = APIRouter(tags=["Admin"])


@router.post(
    f"{settings.API_V1_STR}/admin/roles",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user), Depends(PermissionChecker(["manage_roles"]))],
)
def create_role(role_name: str, db: Session = Depends(get_db)) -> dict[str, str]:
    """
    Создает новую роль в системе.
    Требует права: 'manage_roles'.

    Args:
        role_name (str): Название новой роли.
        db (Session): Сессия базы данных.

    Returns:
        Dict[str, str]: Сообщение об успешном создании.

    Raises:
        HTTPException: Если роль с таким названием уже существует.
    """
    db_role: Role | None = db.query(Role).filter(Role.name == role_name).first()
    if db_role:
        raise HTTPException(status_code=400, detail="Role already exists")
    new_role = Role(name=role_name)
    db.add(new_role)
    db.commit()
    return {"message": f"Role '{role_name}' created successfully."}


@router.post(
    f"{settings.API_V1_STR}/admin/permissions",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user), Depends(PermissionChecker(["manage_permissions"]))],
)
def create_permission(permission_name: str, db: Session = Depends(get_db)) -> dict[str, str]:
    """
    Создает новое разрешение в системе.
    Требует права: 'manage_permissions'.

    Args:
        permission_name (str): Название нового разрешения.
        db (Session): Сессия базы данных.

    Returns:
        Dict[str, str]: Сообщение об успешном создании.

    Raises:
        HTTPException: Если разрешение с таким названием уже существует.
    """
    db_permission: Permission | None = db.query(Permission).filter(Permission.name == permission_name).first()
    if db_permission:
        raise HTTPException(status_code=400, detail="Permission already exists")
    new_permission = Permission(name=permission_name)
    db.add(new_permission)
    db.commit()
    return {"message": f"Permission '{permission_name}' created successfully."}


@router.post(
    f"{settings.API_V1_STR}/admin/roles/{{role_name}}/permissions",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_current_user), Depends(PermissionChecker(["assign_permissions"]))],
)
def assign_permission_to_role(role_name: str, permission_name: str, db: Session = Depends(get_db)) -> dict[str, str]:
    """
    Назначает разрешение существующей роли.
    Требует права: 'assign_permissions'.

    Args:
        role_name (str): Название роли, которой назначается разрешение.
        permission_name (str): Название назначаемого разрешения.
        db (Session): Сессия базы данных.

    Returns:
        Dict[str, str]: Сообщение об успешном назначении.

    Raises:
        HTTPException: Если роль или разрешение не найдены, или если разрешение уже назначено.
    """
    role: Role | None = db.query(Role).filter(Role.name == role_name).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    permission: Permission | None = db.query(Permission).filter(Permission.name == permission_name).first()
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    if permission in role.permissions:
        raise HTTPException(status_code=400, detail="Permission already assigned to this role")

    role.permissions.append(permission)
    db.commit()
    return {"message": f"Permission '{permission_name}' assigned to role '{role_name}'."}


@router.post(
    f"{settings.API_V1_STR}/admin/users/{{user_id}}/roles",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_current_user), Depends(PermissionChecker(["assign_roles"]))],
)
def assign_role_to_user(user_id: str, role_name: str, db: Session = Depends(get_db)) -> dict[str, str]:
    """
    Назначает роль существующему пользователю.
    Требует права: 'assign_roles'.

    Args:
        user_id (str): ID пользователя, которому назначается роль.
        role_name (str): Название назначаемой роли.
        db (Session): Сессия базы данных.

    Returns:
        Dict[str, str]: Сообщение об успешном назначении.

    Raises:
        HTTPException: Если пользователь или роль не найдены, или если роль уже назначена.
    """
    user: User | None = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    role: Role | None = db.query(Role).filter(Role.name == role_name).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role in user.roles:
        raise HTTPException(status_code=400, detail="Role already assigned to this user")

    user.roles.append(role)
    db.commit()
    return {"message": f"Role '{role_name}' assigned to user '{user.email}'."}
