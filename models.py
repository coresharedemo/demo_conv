from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import datetime
import re # Para validación de contraseña

db = SQLAlchemy()

# Tabla de asociación para aplicaciones (muchos a muchos entre User y Convocatoria, con datos extra)
# Esto es un ejemplo, podría simplificarse o hacerse más complejo
# class Aplicacion(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
#     convocatoria_id = db.Column(db.Integer, db.ForeignKey('convocatoria.id'))
#     fecha_aplicacion = db.Column(db.DateTime, default=datetime.datetime.utcnow)
#     estado = db.Column(db.String(100), default='En análisis de documentos') # Estado inicial
#     # Aquí irían referencias a los documentos cargados para ESTA aplicación específica
#     documentos = db.relationship('Documento', backref='aplicacion', lazy='dynamic')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), nullable=False)
    apellido = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256)) # Aumentado tamaño para hashes más seguros
    is_active = db.Column(db.Boolean, default=False) # Inactivo hasta confirmar email
    is_admin = db.Column(db.Boolean, default=False)
    # Relación con aplicaciones (si se usa la tabla intermedia)
    # aplicaciones = db.relationship('Aplicacion', backref='candidato', lazy='dynamic')

    def set_password(self, password):
        # Validación de contraseña (Req 1)
        if (len(password) < 10 or
                not re.search("[a-z]", password) or
                not re.search("[A-Z]", password) or
                not re.search("[0-9]", password) or
                not re.search("[!@#$%^&*()_+-={};':\"|,.<>/?`~]", password)):
            raise ValueError("La contraseña no cumple los requisitos mínimos de seguridad.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'

class Convocatoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    fecha_inicio = db.Column(db.DateTime, nullable=False, index=True)
    fecha_fin = db.Column(db.DateTime, nullable=False, index=True)
    # Relación con aplicaciones (si se usa la tabla intermedia)
    # aplicantes = db.relationship('Aplicacion', backref='convocatoria', lazy='dynamic')

    @property
    def estado(self):
        now = datetime.datetime.utcnow()
        if now < self.fecha_inicio:
            return "Por iniciar"
        elif self.fecha_inicio <= now <= self.fecha_fin:
            return "En proceso de recepción"
        else:
            return "Cerrada"

    def __repr__(self):
        return f'<Convocatoria {self.titulo}>'

# Podrías tener un modelo para Documentos también
# class Documento(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     filename = db.Column(db.String(200))
#     path = db.Column(db.String(500)) # Path en el sistema de archivos o URL de S3/GCS/Azure Blob
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # Quién lo subió
#     aplicacion_id = db.Column(db.Integer, db.ForeignKey('aplicacion.id')) # A qué aplicación pertenece

# Podrías tener un modelo para Estados de Aplicación personalizados por el admin
# class EstadoAplicacion(db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    nombre = db.Column(db.String(100), unique=True, nullable=False)
#    # Podría tener un orden, descripción, etc.