from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix
from app.config import Config

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Log in om deze pagina te bekijken."
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    from app.models.pdns_admin import PdnsUser
    return db.session.get(PdnsUser, int(user_id))


def create_app(config_class=Config, **config_overrides):
    flask_app = Flask(__name__)
    flask_app.config.from_object(config_class)
    flask_app.config.update(config_overrides)

    db.init_app(flask_app)
    login_manager.init_app(flask_app)

    proxy_count = flask_app.config.get("PROXY_COUNT", 1)
    if proxy_count > 0:
        flask_app.wsgi_app = ProxyFix(flask_app.wsgi_app, x_for=proxy_count, x_proto=proxy_count)

    with flask_app.app_context():
        from app import models  # noqa: F401 - register models with SQLAlchemy

    from app.routes.health import bp as health_bp
    from app.routes.proxy import bp as proxy_bp
    from app.routes.admin import bp as admin_bp
    from app.routes.auth import bp as auth_bp
    from app.routes.admin_ui import bp as admin_ui_bp

    flask_app.register_blueprint(health_bp)
    flask_app.register_blueprint(proxy_bp)
    flask_app.register_blueprint(admin_bp)
    flask_app.register_blueprint(auth_bp)
    flask_app.register_blueprint(admin_ui_bp)

    return flask_app
