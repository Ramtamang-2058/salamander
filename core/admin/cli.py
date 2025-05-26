
# admin/cli.py - Command line interface for admin management
import click
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash

from database.db_handler import db
from .models import Admin


@click.command()
@click.option('--username', prompt=True, help='Admin username')
@click.option('--email', prompt=True, help='Admin email')
@click.option('--password', prompt=True, hide_input=True, help='Admin password')
@click.option('--role', default='admin', help='Admin role (admin/super_admin)')
@with_appcontext
def create_admin(username, email, password, role):
    """Create a new admin user"""
    try:
        existing_admin = Admin.query.filter(
            (Admin.username == username) | (Admin.email == email)
        ).first()

        if existing_admin:
            click.echo('Username or email already exists!')
            return

        admin = Admin(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role
        )

        db.session.add(admin)
        db.session.commit()

        click.echo(f'Admin {username} created successfully!')

    except Exception as e:
        db.session.rollback()
        click.echo(f'Error creating admin: {str(e)}')


@click.command()
@click.option('--username', prompt=True, help='Admin username to delete')
@with_appcontext
def delete_admin(username):
    """Delete an admin user"""
    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        click.echo('Admin not found!')
        return

    if click.confirm(f'Are you sure you want to delete admin {username}?'):
        try:
            db.session.delete(admin)
            db.session.commit()
            click.echo(f'Admin {username} deleted successfully!')
        except Exception as e:
            db.session.rollback()
            click.echo(f'Error deleting admin: {str(e)}')


@click.command()
@with_appcontext
def list_admins():
    """List all admin users"""
    admins = Admin.query.all()
    if not admins:
        click.echo('No admin users found.')
        return

    click.echo('Admin Users:')
    click.echo('-' * 50)
    for admin in admins:
        status = 'Active' if admin.is_active else 'Inactive'
        click.echo(f'{admin.username} ({admin.email}) - {admin.role} - {status}')


# Register CLI commands
def register_admin_commands(app):
    app.cli.add_command(create_admin)
    app.cli.add_command(delete_admin)
    app.cli.add_command(list_admins)