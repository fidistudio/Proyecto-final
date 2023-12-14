from flask import Flask, request, jsonify, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import sqlite3

app = Flask(__name__, static_url_path='/app/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Definir modelo de la base de datos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

# Clave secreta para la generación de tokens
SECRET_KEY = "@l@niz0"

# Función para conectar a la base de datos
def connect_db():
    conn = sqlite3.connect('usuarios.db')
    return conn, conn.cursor()

@app.route('/') 
def inicio(): 
    return render_template('index.html')

# Ruta para registro de usuarios
@app.route('/register', methods=['POST'])
def register():
    # Obtener datos del formulario
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Invalid request. Missing username, email, or password.'}), 400

    # Generar hash de la contraseña
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    # Verificar si el usuario ya existe por email
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({'error': 'User already exists'}), 400

    # Insertar nuevo usuario
    new_user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()

    # Redirigir al usuario a una página de éxito
    return redirect(url_for('login'))





# Ruta para login de usuarios
@app.route('/login', methods=['POST'])
def login():
    data = request.form  # Cambia a request.form para obtener datos del formulario

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return render_template('login.html', error='Invalid request')

    # Buscar al usuario en la base de datos por email
    user = User.query.filter_by(email=email).first()

    # Si el usuario no existe o la contraseña es incorrecta, mostrar un mensaje de error
    if not user or not check_password_hash(user.password_hash, password):
        return render_template('login.html', error='Invalid username or password')


    # Redirigir a la página 'form.html' si el inicio de sesión es exitoso
        return redirect(url_for('form'))


# Ruta para tu página de inicio
@app.route('/index')
def index():
    return render_template('index.html')

# Ruta para tu página de inicio de sesión
@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/form')
def form():
    return render_template('form.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)