from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, DateTimeLocalField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import re # Para validación de contraseña

# Importa tu modelo User para validar email único si es necesario
from models import User

# Validación personalizada de contraseña
def password_complexity(form, field):
    password = field.data
    if (len(password) < 10 or
            not re.search("[a-z]", password) or
            not re.search("[A-Z]", password) or
            not re.search("[0-9]", password) or
            not re.search("[!@#$%^&*()_+-={};':\"|,.<>/?`~]", password)):
        raise ValidationError('La contraseña debe tener mínimo 10 caracteres, incluir mayúsculas, minúsculas, números y un caracter especial.')

class RegistrationForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(min=2, max=80)])
    apellido = StringField('Apellido', validators=[DataRequired(), Length(min=2, max=80)])
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired(), password_complexity])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrarse')

    # Validar que el email no exista ya
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Ese correo electrónico ya está registrado.')

class LoginForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember_me = BooleanField('Recordarme')
    submit = SubmitField('Iniciar Sesión')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email()])
    submit = SubmitField('Enviar enlace de recuperación')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nueva Contraseña', validators=[DataRequired(), password_complexity])
    confirm_password = PasswordField('Confirmar Nueva Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Restablecer Contraseña')

class ConvocatoriaForm(FlaskForm):
    titulo = StringField('Título', validators=[DataRequired(), Length(max=150)])
    descripcion = TextAreaField('Descripción')
    fecha_inicio = DateTimeLocalField('Fecha y Hora de Inicio', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    fecha_fin = DateTimeLocalField('Fecha y Hora de Fin', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    submit = SubmitField('Guardar Convocatoria')

    def validate_fecha_fin(self, fecha_fin):
        if fecha_fin.data <= self.fecha_inicio.data:
            raise ValidationError('La fecha de fin debe ser posterior a la fecha de inicio.')

# --- Añadir más formularios según necesidad (Editar Usuario, Subir Documentos, etc.) ---