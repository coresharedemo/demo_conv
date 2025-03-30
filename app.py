import os
from urllib.parse import urlsplit # <--- Añade esta línea
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_mail import Mail, Message # Para correos
from itsdangerous import URLSafeTimedSerializer, SignatureExpired # Para tokens seguros
#from werkzeug.urls import url_parse

from config import Config
from models import db, User, Convocatoria # Importa tus modelos
from forms import LoginForm, RegistrationForm, ForgotPasswordForm, ResetPasswordForm, ConvocatoriaForm # Importa tus formularios

# --- Inicialización ---
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db) # Inicializa Flask-Migrate
login = LoginManager(app)
login.login_view = 'login' # Vista a la que redirige si se requiere login
login.login_message = "Por favor, inicia sesión para acceder a esta página."
mail = Mail(app) # Inicializa Flask-Mail
s = URLSafeTimedSerializer(app.config['SECRET_KEY']) # Serializer para tokens

# --- Creación de tablas y admin inicial (si no existe) ---
@app.before_first_request
def create_tables_and_admin():
    # Esto es simple, para producción real usarías `flask db upgrade`
    # db.create_all() # Asegúrate de correr `flask db init` y `flask db migrate` primero localmente

    # Crear usuario administrador si no existe
    admin_email = "admin@gmail.com"
    admin_pass = "mAS3*Q*9C7wMhKP" # ¡CAMBIAR ESTO INMEDIATAMENTE EN PRODUCCIÓN!

    if not User.query.filter_by(email=admin_email).first():
        try:
            admin_user = User(
                nombre='Admin',
                apellido='User',
                email=admin_email,
                is_active=True, # El admin se activa directamente
                is_admin=True
            )
            # ¡Importante! Validar la contraseña al establecerla
            admin_user.set_password(admin_pass)
            db.session.add(admin_user)
            db.session.commit()
            print(f"Usuario administrador '{admin_email}' creado.")
        except ValueError as e:
             print(f"Error al crear admin: La contraseña por defecto no cumple los requisitos: {e}")
             # Considera lanzar una excepción aquí o manejarlo mejor
        except Exception as e:
            db.session.rollback()
            print(f"Error al crear el usuario administrador: {e}")


@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# --- Funciones Auxiliares (Ej: Enviar Correo) ---
def send_email(subject, recipients, text_body, html_body):
    # Implementación básica, necesitarás configurar MAIL_SERVER, etc. en Config
    # Considera hacerlo asíncrono en una aplicación real
    msg = Message(subject, sender=app.config['ADMINS'][0], recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    try:
        mail.send(msg)
        print(f"Correo enviado a {recipients}") # Log para debug
    except Exception as e:
        print(f"Error al enviar correo: {e}") # Log para debug
        # Aquí podrías reintentar o loggear el error de forma más robusta


# --- Rutas Públicas ---
@app.route('/')
def index():
    # Podrías mostrar convocatorias activas aquí
    convocatorias_activas = Convocatoria.query.filter(
        Convocatoria.fecha_inicio <= datetime.datetime.utcnow(),
        Convocatoria.fecha_fin >= datetime.datetime.utcnow()
    ).order_by(Convocatoria.fecha_inicio).all()
    return render_template('public/index.html', title='Inicio', convocatorias=convocatorias_activas)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard')) # O admin_dashboard si es admin
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Correo o contraseña inválidos', 'danger')
            return redirect(url_for('login'))
        if not user.is_active:
            flash('Tu cuenta no está activa. Por favor, revisa tu correo para el enlace de confirmación.', 'warning')
            # Podrías añadir lógica para reenviar confirmación aquí
            return redirect(url_for('login'))

        login_user(user, remember=form.remember_me.data)
        flash('Inicio de sesión exitoso!', 'success')

        # Redirigir a la página que intentaba acceder o al dashboard
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            if user.is_admin:
                next_page = url_for('admin_dashboard')
            else:
                next_page = url_for('user_dashboard')
        return redirect(next_page)
    return render_template('public/login.html', title='Iniciar Sesión', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(
                nombre=form.nombre.data,
                apellido=form.apellido.data,
                email=form.email.data
            )
            user.set_password(form.password.data) # Valida y hashea
            user.is_active = False # Empieza inactivo
            db.session.add(user)
            db.session.commit()

            # --- Enviar correo de confirmación ---
            token = s.dumps(user.email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('email/confirm_email.html', confirm_url=confirm_url)
            # send_email('Confirma tu cuenta', [user.email], 'Sigue este enlace para confirmar: {}'.format(confirm_url), html)
            print(f"DEBUG: Enlace de confirmación para {user.email}: {confirm_url}") # Para debug SIN enviar email

            flash('¡Registro exitoso! Revisa tu correo para activar tu cuenta.', 'success')
            return redirect(url_for('login'))
        except ValueError as e:
            flash(f'Error en el registro: {e}', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Ocurrió un error inesperado: {e}', 'danger')

    return render_template('public/register.html', title='Registro', form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        # El token expira después de 1 hora (3600 segundos)
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except SignatureExpired:
        flash('El enlace de confirmación ha expirado.', 'danger')
        return redirect(url_for('login')) # O a una página para reenviar
    except Exception as e:
        flash(f'El enlace de confirmación es inválido o ha ocurrido un error.', 'danger')
        print(f"Error al decodificar token: {e}")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()

    if user.is_active:
        flash('La cuenta ya está activa. Puedes iniciar sesión.', 'info')
    else:
        user.is_active = True
        db.session.commit()
        flash('¡Cuenta activada exitosamente! Ahora puedes iniciar sesión.', 'success')

    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Generar token y enviar correo
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            html = render_template('email/reset_password_email.html', reset_url=reset_url)
            # send_email('Restablecer Contraseña', [user.email], 'Sigue este enlace para restablecer: {}'.format(reset_url), html)
            print(f"DEBUG: Enlace de reseteo para {user.email}: {reset_url}") # Debug
            flash('Se ha enviado un enlace para restablecer tu contraseña a tu correo.', 'info')
        else:
            flash('No se encontró una cuenta con ese correo electrónico.', 'warning')
        return redirect(url_for('login')) # Redirigir a login para evitar mostrar si el email existe
    return render_template('public/forgot_password.html', title='Recuperar Contraseña', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    try:
        # Token expira después de 1 hora (3600 segundos)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('El enlace de restablecimiento ha expirado.', 'danger')
        return redirect(url_for('forgot_password'))
    except Exception:
         flash('El enlace de restablecimiento es inválido.', 'danger')
         return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first_or_404()
    form = ResetPasswordForm()

    if form.validate_on_submit():
        try:
            user.set_password(form.password.data) # Valida y hashea
            db.session.commit()
            flash('Tu contraseña ha sido actualizada. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        except ValueError as e:
             flash(f'Error al guardar contraseña: {e}', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Ocurrió un error inesperado: {e}', 'danger')

    return render_template('public/reset_password.html', title='Restablecer Contraseña', form=form, token=token)


# --- Rutas de Usuario Logueado ---
@app.route('/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
         return redirect(url_for('admin_dashboard')) # Los admins van a su propio dashboard

    # Lógica para el dashboard del usuario normal
    # Mostrar convocatorias abiertas, mis aplicaciones, etc.
    convocatorias_activas = Convocatoria.query.filter(
        Convocatoria.fecha_inicio <= datetime.datetime.utcnow(),
        Convocatoria.fecha_fin >= datetime.datetime.utcnow()
    ).order_by(Convocatoria.fecha_inicio).all()
    # Faltaría obtener las aplicaciones del usuario actual...
    return render_template('user/dashboard.html', title='Mi Panel', convocatorias=convocatorias_activas)

# --- Rutas de Administrador ---
# Decorador personalizado para rutas de admin
from functools import wraps
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Acceso no autorizado.", "danger")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    # Lógica del panel de admin
    user_count = User.query.count()
    convocatoria_count = Convocatoria.query.count()
    return render_template('admin/dashboard.html', title='Panel Admin', user_count=user_count, convocatoria_count=convocatoria_count)

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.order_by(User.apellido).all()
    return render_template('admin/manage_users.html', title='Gestionar Usuarios', users=users)

@app.route('/admin/users/toggle_active/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user_active(user_id):
    user = User.query.get_or_404(user_id)
    if user.email == "admin@gmail.com": # Proteger al admin principal
        flash("No se puede desactivar al administrador principal.", "danger")
        return redirect(url_for('manage_users'))
    user.is_active = not user.is_active
    db.session.commit()
    status = "activado" if user.is_active else "desactivado"
    flash(f"Usuario {user.email} {status}.", "success")
    return redirect(url_for('manage_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.email == "admin@gmail.com": # Proteger al admin principal
        flash("No se puede eliminar al administrador principal.", "danger")
        return redirect(url_for('manage_users'))
    # Aquí deberías añadir lógica para manejar/eliminar datos asociados (aplicaciones, documentos)
    # ¡CUIDADO! Esto es destructivo. Considera una desactivación o borrado lógico.
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f"Usuario {user.email} eliminado permanentemente.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar usuario: {e}", "danger")
    return redirect(url_for('manage_users'))


@app.route('/admin/convocatorias', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_convocatorias():
    form = ConvocatoriaForm()
    if form.validate_on_submit():
        try:
            nueva_convocatoria = Convocatoria(
                titulo=form.titulo.data,
                descripcion=form.descripcion.data,
                fecha_inicio=form.fecha_inicio.data,
                fecha_fin=form.fecha_fin.data
            )
            db.session.add(nueva_convocatoria)
            db.session.commit()
            flash('Convocatoria creada exitosamente!', 'success')
            return redirect(url_for('manage_convocatorias'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear convocatoria: {e}', 'danger')

    convocatorias = Convocatoria.query.order_by(Convocatoria.fecha_inicio.desc()).all()
    return render_template('admin/manage_convocatorias.html', title='Gestionar Convocatorias', convocatorias=convocatorias, form=form)

# --- Añadir rutas para editar/eliminar convocatorias, ver aplicaciones, cambiar estados, etc. ---


# --- CLI Commands (Flask-Migrate) ---
# Para usar esto, instala Flask-Migrate y ejecuta en la terminal:
# export FLASK_APP=app.py  (o set FLASK_APP=app.py en Windows)
# flask db init          (Solo la primera vez)
# flask db migrate -m "Mensaje descriptivo del cambio" (Cada vez que cambies models.py)
# flask db upgrade       (Para aplicar los cambios a la DB)

# --- Ejecución ---
if __name__ == '__main__':
    # Crear la carpeta instance si no existe (para SQLite local)
    instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    # Correr la aplicación en modo debug localmente
    app.run(debug=True)
