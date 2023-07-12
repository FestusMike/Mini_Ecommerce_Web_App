from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://root:Timi1234@localhost/market'
app.config['SECRET_KEY'] = '78d78d45a2c97b1911b1801e'
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '6d4089c7209c16'
app.config['MAIL_PASSWORD'] = '26f27b6fac36de'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['UPLOAD_FOLDER'] = 'C:\\Users\\Micheal\\Desktop\\web_pictures'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max-limit.


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)
csrf = CSRFProtect(app)


with app.app_context():
    db.create_all()

from market import routes

if __name__ == '__main__':
    app.run(debug=True)