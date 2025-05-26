from werkzeug.security import generate_password_hash

from core.admin.models import Admin
from database.db_handler import db


def create_first_admin():
    """Create the first super admin user"""
    print("Creating first admin user...")

    username = input("Enter admin username: ").strip()
    email = input("Enter admin email: ").strip()
    password = input("Enter admin password: ").strip()

    if not username or not email or not password:
        print("All fields are required!")
        return False

    try:
        # Check if admin already exists
        existing_admin = Admin.query.filter(
            (Admin.username == username) | (Admin.email == email)
        ).first()

        if existing_admin:
            print("Username or email already exists!")
            return False

        # Create admin
        admin = Admin(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role='super_admin'
        )

        db.session.add(admin)
        db.session.commit()

        print(f"Super admin '{username}' created successfully!")
        print(f"You can now login at /admin/login")
        return True

    except Exception as e:
        db.session.rollback()
        print(f"Error creating admin: {str(e)}")
        return False


def create_admin_tables():
    """Create admin tables"""
    try:
        from core.admin.models import Admin, AdminLog
        db.create_all()
        print("Admin tables created successfully!")
        return True
    except Exception as e:
        print(f"Error creating admin tables: {str(e)}")
        return False

