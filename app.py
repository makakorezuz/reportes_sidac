from flask import Flask, render_template, redirect, url_for
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bootstrap import Bootstrap

app = Flask(__name__)

#llave de secreta para el uso de la aplicación
app.config['SECRET_KEY'] = 'Estadebeserlallavesecreta'

#configuración del sistema de la base de datos POSTGRESQL con la librería SQLALCHEMY
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://usuario:contrasenia@localhost/flask_dashsidac'

bootstrap = Bootstrap(app)

db = SQLAlchemy(app)

#creación de las instancias para el manejo de sesiones 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    """ Creación del modelo de usuario en el que se ingresará 
        y consultará usuario-contraseña
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    """ Declaración de las validaciones que se harán en el
        formulario de acceso, usuario minimi de caracteres 4 y máximo 15
        contraseña de acceso, contraseña minimo de 4 caracteres y máximo de 15
    """
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    """ Declaración de las validaciones que se harán en el
        formulario de registro, usuario minimi de caracteres 4 y máximo 15
        contraseña de registro, contraseña minima de 8 caracteres y maximo 80
    """
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    """ Ruta para el inicio de la aplicación que renderiza a index.html"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Ruta para el acceso a la aplicación que renderiza a login.html"""
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Usuario o contraseña inválida</h1>'
        

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """ Ruta para el registro de usuario renderiza a signup.html 
        Si un usuario no está registrado aquí se puede hacer el registro
        --- Modificar para que esto solo se pueda hacer mediante el ingreso de un usuario
        --- predefinido y no sea de manera abierta
    """
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>El usuario ha sido creado</h1>'
        

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    """ Ruta para ver las estadíticas del SIDAC renderiza a dashboard.html """ 
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    """ Ruta para la salida del sistema, redirecciona al index (función index)"""
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
