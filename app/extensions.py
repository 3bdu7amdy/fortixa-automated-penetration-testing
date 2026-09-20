"""Flask extensions - initialized here to avoid circular imports."""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


@login_manager.user_loader
def load_user(user_id):
    """Load a user from the database by ID."""
    from app.models.user import User
    return db.session.get(User, int(user_id))
