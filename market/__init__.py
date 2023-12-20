from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import os
from flask_migrate import Migrate

app = Flask(__name__)

SQLALCHEMY_DATABASE_URI = "mysql+mysqldb://{username}:{password}@{hostname}/{databasename}".format(
    username= os.environ.get('MYSQL_USER'),
    password= os.environ.get('MYSQL_PASSWORD'),
    hostname= os.environ.get('MYSQL_HOST'),
    databasename= os.environ.get('MYSQL_DB')
)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')



db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate(app, db)

from market import routes

if __name__ == '__main__':
	app.run(debug=True)

 