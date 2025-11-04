from app.core.security import get_password_hash
from app.database.models.rbac import Permission
from app.database.models.rbac import Role
from app.database.models.user import User
from sqlalchemy.orm import Session


def init_db(db: Session) -> None:
    """
    Инициализирует базу данных начальными данными.

    Создает набор разрешений, две основные роли ('admin', 'user'),
    назначает им права и создает пользователя-администратора по умолчанию,
    если они еще не существуют.

    Args:
        db (Session): Сессия базы данных.
    """
    permissions = {
        "view_user_resource",
        "view_admin_resource",
        "manage_roles",
        "manage_permissions",
        "assign_permissions",
        "assign_roles",
    }
    for perm_name in permissions:
        if not db.query(Permission).filter(Permission.name == perm_name).first():
            db.add(Permission(name=perm_name))
    db.commit()

    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        user_role = Role(name="user")
        user_perm = db.query(Permission).filter(Permission.name == "view_user_resource").one()
        user_role.permissions.append(user_perm)
        db.add(user_role)

    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(name="admin")
        all_permissions = db.query(Permission).all()
        admin_role.permissions.extend(all_permissions)
        db.add(admin_role)

    db.commit()

    admin_user = db.query(User).filter(User.email == "admin@example.com").first()
    if not admin_user:
        admin_user = User(
            email="admin@example.com",
            hashed_password=get_password_hash("adminpassword"),
            full_name="Admin User",
            is_active=True,
            roles=[admin_role],
        )
        db.add(admin_user)

    db.commit()
    print("Database has been initialized with default roles, permissions, and admin user.")
