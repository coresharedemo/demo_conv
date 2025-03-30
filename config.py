import os
from dotenv import load_dotenv

load_dotenv() # Carga variables desde un archivo .env si existe (para desarrollo local)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'una-clave-secreta-muy-dificil-de-adivinar' # ¡Cambiar y usar variable de entorno!
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Render proveerá DATABASE_URL como variable de entorno apuntando a PostgreSQL
    # Para desarrollo local, usaremos SQLite
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'app.db')

    # Configuración de Email (ejemplo, necesitarás configurar un servicio real)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') # Ej: smtp.googlemail.com
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') # Tu correo
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') # Tu contraseña de aplicación
    ADMINS = ['admin@example.com'] # Correo a donde enviar errores