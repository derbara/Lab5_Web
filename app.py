from flask import Flask, render_template, redirect, url_for, request, flash, session, Blueprint, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import mysql.connector
from mysql.connector import Error
import hashlib
import re
from datetime import datetime
from functools import wraps
import csv
import io

app = Flask(__name__)
app.secret_key = '123'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к этой странице необходимо войти в систему.'
login_manager.login_message_category = 'warning'

# DB Config 
DB_CONFIG = {
    'host': 'localhost',
    'database': 'lab4_db',
    'user': 'root',
    'password': 'Yasya2006'
}

# Получает подключение к БД, возвращает None при ошибке
def get_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print("DB ERROR:", e)
        return None

# Хеширует пароль с использованием SHA256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Декоратор для проверки прав доступа (использует role_id: 1 = администратор)
def check_rights(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Если пользователь не авторизован, отправляем на логин
            if not current_user.is_authenticated:
                flash('Для доступа к этой странице необходимо войти в систему.', 'warning')
                return redirect(url_for('login', next=request.url))
            
            # Проверяем наличие нужных прав
            if required_role == 'admin' and current_user.role_id != 1:
                flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Класс пользователя для работы с Flask-Login
class User(UserMixin):
    def __init__(self, id, login, last_name, first_name, middle_name, role_id, role_name):
        self.id = id
        self.login = login
        self.last_name = last_name
        self.first_name = first_name
        self.middle_name = middle_name
        self.role_id = role_id
        self.role_name = role_name

    @property
    # Возвращает полное имя или логин если имя не заполнено
    def full_name(self):
        parts = [self.last_name or '', self.first_name or '', self.middle_name or '']
        return ' '.join(p for p in parts if p).strip() or self.login

@login_manager.user_loader
# Загружает данные пользователя из БД для Flask-Login по его ID
def load_user(user_id):
    conn = get_db()
    if not conn:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        # Получаем пользователя с его ролью
        cursor.execute("""
            SELECT u.*, r.name as role_name 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.id 
            WHERE u.id = %s
        """, (user_id,))
        row = cursor.fetchone()
        if row:
            return User(row['id'], row['login'], row['last_name'], row['first_name'],
                       row['middle_name'], row['role_id'], row.get('role_name'))
        return None
    finally:
        cursor.close()
        conn.close()

# Регистрирует каждое посещение страницы в visit_logs таблице
@app.before_request
def log_visit():
    # Не регистрируем статические файлы
    if request.endpoint and not request.endpoint.startswith('static') and request.endpoint != 'static':
        path = request.path
        user_id = current_user.id if current_user.is_authenticated else None
        
        conn = get_db()
        if conn:
            try:
                cursor = conn.cursor()
                # Вставляем запись о посещении
                cursor.execute("""
                    INSERT INTO visit_logs (path, user_id, created_at)
                    VALUES (%s, %s, %s)
                """, (path, user_id, datetime.now()))
                conn.commit()
            except Error as e:
                print(f"Error logging visit: {e}")
            finally:
                cursor.close()
                conn.close()

# Проверяет валидность логина: не меньше 5 символов, только латиница и цифры
def validate_login(login):
    if not login:
        return 'Поле не может быть пустым'
    if len(login) < 5:
        return 'Логин должен содержать не менее 5 символов'
    if not re.match(r'^[a-zA-Z0-9]+$', login):
        return 'Логин должен состоять только из латинских букв и цифр'
    return None

#валидация
def validate_password(password):
    if not password:
        return 'Поле не может быть пустым'
    if len(password) < 8:
        return 'Пароль должен содержать не менее 8 символов'
    if len(password) > 128:
        return 'Пароль должен содержать не более 128 символов'
    if ' ' in password:
        return 'Пароль не должен содержать пробелы'
    if not re.search(r'[A-ZА-ЯЁ]', password):
        return 'Пароль должен содержать хотя бы одну заглавную букву'
    if not re.search(r'[a-zа-яё]', password):
        return 'Пароль должен содержать хотя бы одну строчную букву'
    if not re.search(r'[0-9]', password):
        return 'Пароль должен содержать хотя бы одну цифру'
    # Проверяем разрешенные спецсимволы
    allowed = r'^[a-zA-Zа-яА-ЯёЁ0-9~!?@#$%^&*_\-+()\[\]{}<>/\\|"\'.,:;]+$'
    if not re.match(allowed, password):
        return 'Пароль содержит недопустимые символы'
    return None

# Получает список всех ролей из БД
def get_roles():
    conn = get_db()
    if not conn:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM roles ORDER BY name")
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

# Маршрут для главной страницы - выводит список всех пользователей
@app.route('/')
def index():
    conn = get_db()
    users = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT u.id, u.login, u.last_name, u.first_name, u.middle_name, r.name as role_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                ORDER BY u.id
            """)
            users = cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    return render_template('index.html', users=users)

# Маршрут для входа в систему (GET - форма, POST - обработка логина)
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Если пользователь уже вавлогинен, показываем главную
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        login_val = request.form.get('login', '').strip()
        password = request.form.get('password', '')
        
        conn = get_db()
        if not conn:
            flash('Ошибка подключения к базе данных', 'danger')
            return render_template('login.html')
        
        try:
            cursor = conn.cursor(dictionary=True)
            # Поиск пользователя с совпадающим логином и паролем
            cursor.execute("""
                SELECT u.*, r.name as role_name 
                FROM users u 
                LEFT JOIN roles r ON u.role_id = r.id 
                WHERE u.login = %s AND u.password_hash = %s
            """, (login_val, hash_password(password)))
            row = cursor.fetchone()
            
            if row:
                # Логин успешный
                user = User(row['id'], row['login'], row['last_name'], row['first_name'],
                           row['middle_name'], row['role_id'], row.get('role_name'))
                login_user(user)
                flash('Вы успешно вошли в систему', 'success')
                # Перенаправляем на требуемую страницу или на главную
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                # Неверные учытные данные
                flash('Неверный логин или пароль', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('login.html')

# Маршрут для выхода из системы (0 только для авторизованных)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# Маршрут для просмотра профиля пользователя
# Админ может смотреть всех, обычный пользователь - только себя
@app.route('/users/<int:user_id>')
@login_required
def view_user(user_id):
    if current_user.role_id != 1 and current_user.id != user_id:
        flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.*, r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = %s
        """, (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('index'))
        return render_template('view_user.html', user=user)
    finally:
        cursor.close()
        conn.close()

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@check_rights('admin')
def create_user():
    roles = get_roles()
    errors = {}
    form_data = {}

    if request.method == 'POST':
        form_data = {
            'login': request.form.get('login', '').strip(),
            'password': request.form.get('password', ''),
            'last_name': request.form.get('last_name', '').strip(),
            'first_name': request.form.get('first_name', '').strip(),
            'middle_name': request.form.get('middle_name', '').strip(),
            'role_id': request.form.get('role_id', '') or None,
        }

        login_err = validate_login(form_data['login'])
        if login_err:
            errors['login'] = login_err

        pwd_err = validate_password(form_data['password'])
        if pwd_err:
            errors['password'] = pwd_err

        if not form_data['first_name']:
            errors['first_name'] = 'Поле не может быть пустым'

        if errors:
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='create')

        conn = get_db()
        if not conn:
            flash('Ошибка подключения к базе данных', 'danger')
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='create')
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                form_data['login'],
                hash_password(form_data['password']),
                form_data['last_name'] or None,
                form_data['first_name'],
                form_data['middle_name'] or None,
                form_data['role_id'],
                datetime.now()
            ))
            conn.commit()
            flash('Пользователь успешно создан', 'success')
            return redirect(url_for('index'))
        except Error as e:
            flash(f'Ошибка при сохранении: {e}', 'danger')
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='create')
        finally:
            cursor.close()
            conn.close()

    return render_template('user_form.html', roles=roles, errors=errors,
                           form_data=form_data, mode='create')

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Проверка прав: админ может редактировать всех, пользователь только себя
    if current_user.role_id != 1 and current_user.id != user_id:
        flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
        return redirect(url_for('index'))
    
    roles = get_roles()
    errors = {}
    is_admin = current_user.role_id == 1

    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        form_data = {
            'last_name': request.form.get('last_name', '').strip(),
            'first_name': request.form.get('first_name', '').strip(),
            'middle_name': request.form.get('middle_name', '').strip(),
            'role_id': request.form.get('role_id', '') or None if is_admin else None,
        }

        if not form_data['first_name']:
            errors['first_name'] = 'Поле не может быть пустым'

        if errors:
            conn.close()
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='edit', user_id=user_id, is_admin=is_admin)

        try:
            cursor = conn.cursor()
            if is_admin:
                cursor.execute("""
                    UPDATE users SET last_name=%s, first_name=%s, middle_name=%s, role_id=%s
                    WHERE id=%s
                """, (
                    form_data['last_name'] or None,
                    form_data['first_name'],
                    form_data['middle_name'] or None,
                    form_data['role_id'],
                    user_id
                ))
            else:
                cursor.execute("""
                    UPDATE users SET last_name=%s, first_name=%s, middle_name=%s
                    WHERE id=%s
                """, (
                    form_data['last_name'] or None,
                    form_data['first_name'],
                    form_data['middle_name'] or None,
                    user_id
                ))
            conn.commit()
            flash('Данные пользователя обновлены', 'success')
            return redirect(url_for('index'))
        except Error as e:
            flash(f'Ошибка при сохранении: {e}', 'danger')
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='edit', user_id=user_id, is_admin=is_admin)
        finally:
            cursor.close()
            conn.close()

    # GET - открытие пользователя
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.*, r.name as role_name 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.id 
            WHERE u.id = %s
        """, (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('index'))
        form_data = {
            'last_name': user['last_name'] or '',
            'first_name': user['first_name'] or '',
            'middle_name': user['middle_name'] or '',
            'role_id': user['role_id'] or '',
            'role_name': user['role_name'] or '—',
        }
        return render_template('user_form.html', roles=roles, errors=errors,
                               form_data=form_data, mode='edit', user_id=user_id, is_admin=is_admin)
    finally:
        cursor.close()
        conn.close()

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@check_rights('admin')
def delete_user(user_id):
    if user_id == 21:
        flash('Нельзя удалить главного администратора', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor(dictionary=True)  # ← ИЗМЕНИЛИ: добавили dictionary=True
        
        # Получаем информацию о пользователе (нужно для проверки роли)
        cursor.execute("SELECT role_id FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('index'))
        
        if user['role_id'] == 1:
            # Считаем сколько всего админов в системе
            cursor.execute("SELECT COUNT(*) as admin_count FROM users WHERE role_id = 1")
            result = cursor.fetchone()
            admin_count = result['admin_count']
            
            # Если это последний админ - запрещаем удаление
            if admin_count <= 1:
                flash('Нельзя удалить последнего администратора системы!', 'danger')
                return redirect(url_for('index'))
        
        
        # Удаление (возвращаемся к обычному курсору или используем dictionary=True)
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        flash('Пользователь удалён', 'success')
        
    except Error as e:
        flash(f'Ошибка при удалении: {e}', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    errors = {}

    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        conn = get_db()
        if not conn:
            flash('Ошибка подключения к базе данных', 'danger')
            return render_template('change_password.html', errors=errors)

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT password_hash FROM users WHERE id=%s", (current_user.id,))
            row = cursor.fetchone()

            if not row or row['password_hash'] != hash_password(old_password):
                errors['old_password'] = 'Неверный текущий пароль'

            pwd_err = validate_password(new_password)
            if pwd_err:
                errors['new_password'] = pwd_err

            if new_password != confirm_password:
                errors['confirm_password'] = 'Пароли не совпадают'

            if errors:
                return render_template('change_password.html', errors=errors)

            cursor.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                          (hash_password(new_password), current_user.id))
            conn.commit()
            flash('Пароль успешно изменён', 'success')
            return redirect(url_for('index'))
        except Error as e:
            flash(f'Ошибка: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('change_password.html', errors=errors)

# Blueprint для статистики и отчётов 
reports_bp = Blueprint('reports', __name__, url_prefix='/reports')

@reports_bp.route('/visit-log')
@login_required
def visit_log():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page #пагинация
    
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        if current_user.role_id == 1:
            cursor.execute("SELECT COUNT(*) as total FROM visit_logs")
            total = cursor.fetchone()['total']
            #v.path - URL страницы
            cursor.execute("""
                SELECT v.id, v.path, v.user_id, v.created_at, 
                       CONCAT_WS(' ', u.last_name, u.first_name, u.middle_name) as user_name
                FROM visit_logs v
                LEFT JOIN users u ON v.user_id = u.id
                ORDER BY v.created_at DESC
                LIMIT %s OFFSET %s
            """, (per_page, offset))
        else:
            cursor.execute("SELECT COUNT(*) as total FROM visit_logs WHERE user_id = %s", (current_user.id,))
            total = cursor.fetchone()['total']
            
            cursor.execute("""
                SELECT v.id, v.path, v.user_id, v.created_at,
                       CONCAT_WS(' ', u.last_name, u.first_name, u.middle_name) as user_name
                FROM visit_logs v
                LEFT JOIN users u ON v.user_id = u.id
                WHERE v.user_id = %s
                ORDER BY v.created_at DESC
                LIMIT %s OFFSET %s
            """, (current_user.id, per_page, offset))
        
        logs = cursor.fetchall() #получает все строки результата
        
        for log in logs:
            if isinstance(log['created_at'], datetime):
                log['created_at'] = log['created_at'].strftime('%d.%m.%Y %H:%M:%S')
            if not log['user_name']:
                log['user_name'] = 'Неаутентифицированный пользователь'        
        total_pages = (total + per_page - 1) // per_page
        
        return render_template('logs.html', logs=logs, page=page, 
                             total_pages=total_pages, total=total, per_page=per_page)
    finally:
        cursor.close()
        conn.close()

@reports_bp.route('/by-pages') #строит отчет
@login_required
def by_pages():
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        if current_user.role_id == 1:
            cursor.execute("""
                SELECT path, COUNT(*) as visit_count
                FROM visit_logs
                GROUP BY path
                ORDER BY visit_count DESC
            """)
        else:
            cursor.execute("""
                SELECT path, COUNT(*) as visit_count
                FROM visit_logs
                WHERE user_id = %s
                GROUP BY path
                ORDER BY visit_count DESC
            """, (current_user.id,))
        
        stats = cursor.fetchall()
        return render_template('report_pages.html', stats=stats)
    finally:
        cursor.close()
        conn.close()

@reports_bp.route('/export-pages-csv')
@login_required
def export_pages_csv():
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        if current_user.role_id == 1:
            cursor.execute("""
                SELECT path, COUNT(*) as visit_count
                FROM visit_logs
                GROUP BY path
                ORDER BY visit_count DESC
            """)
        else:
            cursor.execute("""
                SELECT path, COUNT(*) as visit_count
                FROM visit_logs
                WHERE user_id = %s
                GROUP BY path
                ORDER BY visit_count DESC
            """, (current_user.id,))
        
        stats = cursor.fetchall()
        
        output = io.StringIO() # создаёт строковый буфер в памяти
        writer = csv.writer(output, delimiter=';')
        writer.writerow(['№', 'Страница', 'Количество посещений']) # заголовок
        
        for i, row in enumerate(stats, 1):
            writer.writerow([i, row['path'], row['visit_count']])
        
        output.seek(0) # перематывает буфер в начало
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8-sig')),
            mimetype='text/csv',
            as_attachment=True,  # браузер скачивает, а не открывает
            download_name='report_pages.csv'
        )
    finally:
        cursor.close()
        conn.close()

@reports_bp.route('/by-users') #сколько страниц посетил каждый пользователь
@login_required
@check_rights('admin')
def by_users():
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN v.user_id IS NULL THEN 'Неаутентифицированный пользователь'
                    ELSE CONCAT_WS(' ', u.last_name, u.first_name, u.middle_name)
                END as user_name,
                COUNT(*) as visit_count
            FROM visit_logs v
            LEFT JOIN users u ON v.user_id = u.id
            GROUP BY user_name
            ORDER BY visit_count DESC
        """)
        
        stats = cursor.fetchall()
        return render_template('report_users.html', stats=stats)
    finally:
        cursor.close()
        conn.close()

@reports_bp.route('/export-users-csv') #строит csv файл
@login_required
@check_rights('admin')
def export_users_csv():
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN v.user_id IS NULL THEN 'Неаутентифицированный пользователь'
                    ELSE CONCAT_WS(' ', u.last_name, u.first_name, u.middle_name)
                END as user_name,
                COUNT(*) as visit_count
            FROM visit_logs v
            LEFT JOIN users u ON v.user_id = u.id
            GROUP BY user_name
            ORDER BY visit_count DESC
        """)
        
        stats = cursor.fetchall()
        
        output = io.StringIO()
        writer = csv.writer(output, delimiter=';')
        writer.writerow(['Пользователь', 'Количество посещений'])
        
        for i, row in enumerate(stats, 1): #Перебор строк статистики
            writer.writerow([row['user_name'], row['visit_count']])
        
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8-sig')), #создает бинарный файл в памяти
            mimetype='text/csv',
            as_attachment=True,
            download_name='report_users.csv'
        )
    finally:
        cursor.close()
        conn.close()

# Регистрируем blueprint
app.register_blueprint(reports_bp)

if __name__ == '__main__':
    app.run(debug=True)