import base64
import json
import os
import secrets
import string
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    has_request_context,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
LOG_DIR = DATA_DIR / 'logs'
APP_LOG_PATH = LOG_DIR / 'application.jsonl'
load_dotenv(BASE_DIR / '.env')

ROLE_STAFF = 'STAFF'
ROLE_OPERATOR = 'OPERATOR'
ROLE_LEAD = 'LEAD'
ROLE_EXEC = 'EXEC'
ROLE_LABELS = {
    ROLE_STAFF: 'Сотрудник',
    ROLE_OPERATOR: 'Оператор',
    ROLE_LEAD: 'Руководитель группы',
    ROLE_EXEC: 'Исполнительный контур',
}
ROLE_ORDER = {
    ROLE_STAFF: 1,
    ROLE_OPERATOR: 2,
    ROLE_LEAD: 3,
    ROLE_EXEC: 4,
}

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / 'app' / 'templates'),
    static_folder=str(BASE_DIR / 'app' / 'static'),
)
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError('SECRET_KEY is required')
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_FILE_SIZE', str(1024 * 1024)))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://postgres:postgres@localhost:5432/cybernet',
)
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql://'):
    try:
        import psycopg2
    except Exception:
        try:
            import psycopg
            app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace(
                'postgresql://',
                'postgresql+psycopg://',
                1,
            )
        except Exception:
            pass
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Требуется авторизация'
login_manager.login_message_category = 'warning'

RATE_LIMIT_STATE = {}


def ensure_runtime_dirs():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def get_client_ip():
    return request.remote_addr if has_request_context() else ''


def check_rate_limit(scope, identity, limit=10, window_seconds=60):
    now = datetime.utcnow()
    key = (scope, identity or 'anonymous')
    window_start = now - timedelta(seconds=window_seconds)
    attempts = [ts for ts in RATE_LIMIT_STATE.get(key, []) if ts > window_start]
    if len(attempts) >= limit:
        RATE_LIMIT_STATE[key] = attempts
        return False
    attempts.append(now)
    RATE_LIMIT_STATE[key] = attempts
    return True


def require_rate_limit(scope, identity=None, limit=10, window_seconds=60):
    identity_value = identity or get_client_ip()
    if not check_rate_limit(scope, identity_value, limit, window_seconds):
        log_event('rate_limit', status='failed', details={'scope': scope, 'identity': identity_value})
        abort(429)


def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


def validate_csrf():
    expected = session.get('_csrf_token')
    supplied = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        log_event('csrf.validation', status='failed')
        abort(403)


def log_event(event_type, status='success', details=None, username=None):
    ensure_runtime_dirs()
    actor = username
    if actor is None:
        try:
            actor = current_user.username if getattr(current_user, 'is_authenticated', False) else 'anonymous'
        except Exception:
            actor = 'system'
    payload = {
        'ts': datetime.utcnow().isoformat() + 'Z',
        'event': event_type,
        'status': status,
        'user': actor,
        'route': request.path if has_request_context() else '',
        'method': request.method if has_request_context() else '',
        'remote_addr': get_client_ip(),
        'details': details or {},
    }
    with APP_LOG_PATH.open('a', encoding='utf-8') as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + '\n')


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(128), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(128), nullable=False)
    role_code = db.Column(db.String(24), nullable=False, default=ROLE_STAFF)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    projects = db.relationship('Project', backref='owner', lazy=True)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    @property
    def role_label(self):
        return ROLE_LABELS.get(self.role_code, self.role_code)

    @property
    def role_rank(self):
        return ROLE_ORDER.get(self.role_code, 0)


class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    summary = db.Column(db.Text, nullable=False, default='')
    is_hidden = db.Column(db.Boolean, default=False, nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    notes = db.relationship('ProjectNote', backref='project', lazy=True, cascade='all, delete-orphan')
    files = db.relationship('ProjectFile', backref='project', lazy=True, cascade='all, delete-orphan')
    invites = db.relationship('ProjectInvite', backref='project', lazy=True, cascade='all, delete-orphan')


class ProjectGrant(db.Model):
    __tablename__ = 'project_grants'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, default='workflow')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ProjectNote(db.Model):
    __tablename__ = 'project_notes'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    body_b64 = db.Column(db.Text, nullable=False)
    body_encoding = db.Column(db.String(16), nullable=False, default='plain')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    author = db.relationship('User', lazy=True)


class ProjectFile(db.Model):
    __tablename__ = 'project_files'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False, index=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    filename = db.Column(db.String(180), nullable=False)
    content_b64 = db.Column(db.Text, nullable=False)
    content_encoding = db.Column(db.String(16), nullable=False, default='plain')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    uploader = db.relationship('User', lazy=True)


class PartnerChannel(db.Model):
    __tablename__ = 'partner_channels'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    sector = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ProjectInvite(db.Model):
    __tablename__ = 'project_invites'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False, index=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('partner_channels.id'), nullable=False, index=True)
    recipient_email = db.Column(db.String(180), nullable=False)
    invite_code = db.Column(db.String(64), nullable=False, unique=True, index=True)
    status = db.Column(db.String(24), nullable=False, default='pending', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    channel = db.relationship('PartnerChannel', lazy=True)


class RecoveryTicket(db.Model):
    __tablename__ = 'recovery_tickets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    token = db.Column(db.String(96), nullable=False, unique=True, index=True)
    status = db.Column(db.String(24), nullable=False, default='approved', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', lazy=True)


class NotebookEntry(db.Model):
    __tablename__ = 'notebook_entries'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class SystemSetting(db.Model):
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    setting_value = db.Column(db.Text, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def get_setting(key, default=''):
    row = SystemSetting.query.filter_by(setting_key=key).first()
    return row.setting_value if row else default


def set_setting(key, value):
    row = SystemSetting.query.filter_by(setting_key=key).first()
    if row:
        row.setting_value = value
    else:
        db.session.add(SystemSetting(setting_key=key, setting_value=value))


def random_token(length=24):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def case_ref(prefix, row_id):
    return f'{prefix}-{int(row_id):06d}'


def parse_case_ref(raw_value, prefix):
    text_value = (raw_value or '').strip().lower()
    normalized_prefix = prefix.lower() + '-'
    if text_value.startswith(normalized_prefix):
        text_value = text_value[len(normalized_prefix):]
    if not text_value.isdigit():
        return None
    return int(text_value)


def encode_text(text_value):
    return base64.b64encode(text_value.encode('utf-8')).decode('ascii')


def decode_text(raw_b64):
    return base64.b64decode(raw_b64.encode('ascii')).decode('utf-8', errors='replace')


def try_decode_base64(raw_value):
    if raw_value is None:
        return None
    text_value = str(raw_value).strip()
    if not text_value:
        return None
    try:
        decoded_bytes = base64.b64decode(text_value, validate=True)
        decoded_text = decoded_bytes.decode('utf-8')
    except Exception:
        return None
    if base64.b64encode(decoded_text.encode('utf-8')).decode('ascii').rstrip('=') != text_value.rstrip('='):
        return None
    return decoded_text


def role_rank(role_code):
    return ROLE_ORDER.get(role_code, 0)


def is_exec(user):
    return bool(user and getattr(user, 'is_authenticated', False) and user.role_code == ROLE_EXEC)


def has_project_grant(user_id, project_id):
    if not user_id:
        return False
    row = ProjectGrant.query.filter_by(user_id=user_id, project_id=project_id).first()
    return row is not None


def can_view_project(user, project):
    if not project:
        return False
    if not project.is_hidden:
        return True
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if user.id == project.owner_id:
        return True
    if user.role_code == ROLE_EXEC:
        return True
    if has_project_grant(user.id, project.id):
        return True
    return False


def can_manage_project(user, project):
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if user.id == project.owner_id:
        return True
    if user.role_code == ROLE_EXEC:
        return True
    return False


def visible_projects_query(user):
    rows = Project.query.order_by(Project.updated_at.desc())
    if user and getattr(user, 'is_authenticated', False):
        if user.role_code == ROLE_EXEC:
            return rows
        grant_ids = [g.project_id for g in ProjectGrant.query.filter_by(user_id=user.id).all()]
        if grant_ids:
            return rows.filter(
                (Project.is_hidden.is_(False)) |
                (Project.owner_id == user.id) |
                (Project.id.in_(grant_ids))
            )
        return rows.filter(
            (Project.is_hidden.is_(False)) |
            (Project.owner_id == user.id)
        )
    return rows.filter(Project.is_hidden.is_(False))


def generate_invite_code(project_id, channel_id):
    _ = (project_id, channel_id)
    while True:
        candidate = base64.urlsafe_b64encode(os.urandom(24)).decode('ascii').rstrip('=')[:32]
        exists = ProjectInvite.query.filter_by(invite_code=candidate).first()
        if not exists:
            return candidate


def add_project_grant_if_missing(user_id, project_id, source):
    exists = ProjectGrant.query.filter_by(project_id=project_id, user_id=user_id).first()
    if exists:
        return False
    db.session.add(ProjectGrant(project_id=project_id, user_id=user_id, source=source))
    return True


def search_notebook(user_id, query_text):
    if not query_text:
        rows = NotebookEntry.query.filter_by(user_id=user_id).order_by(NotebookEntry.created_at.desc()).limit(40).all()
        return rows, None
    pattern = f'%{query_text}%'
    rows = (
        NotebookEntry.query
        .filter(
            NotebookEntry.user_id == user_id,
            (NotebookEntry.title.ilike(pattern)) | (NotebookEntry.body.ilike(pattern)),
        )
        .order_by(NotebookEntry.created_at.desc())
        .limit(40)
        .all()
    )
    return rows, None


def _table_exists(conn, table_name):
    return inspect(conn).has_table(table_name)


def _column_names(conn, table_name):
    return {c['name'] for c in inspect(conn).get_columns(table_name)}


def _add_column(conn, table_name, column_name, column_ddl):
    if not _table_exists(conn, table_name):
        return
    if column_name in _column_names(conn, table_name):
        return
    conn.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} {column_ddl}'))


def run_schema_migrations():
    conn = db.engine.connect()
    tx = conn.begin()
    try:
        if _table_exists(conn, 'users'):
            _add_column(conn, 'users', 'role_code', 'VARCHAR(24)')
            _add_column(conn, 'users', 'is_admin', 'BOOLEAN DEFAULT FALSE')
            _add_column(conn, 'users', 'created_at', 'TIMESTAMP')
            _add_column(conn, 'users', 'full_name', 'VARCHAR(128)')

            user_cols = _column_names(conn, 'users')
            if 'role_name' in user_cols:
                conn.execute(text("""
                    UPDATE users
                    SET role_code = CASE
                        WHEN role_code IS NOT NULL AND role_code <> '' THEN role_code
                        WHEN role_name IN ('DIRECTOR', 'EXEC', 'L4', 'ADMIN') THEN 'EXEC'
                        WHEN role_name IN ('NETRUNNER', 'LEAD', 'L3') THEN 'LEAD'
                        WHEN role_name IN ('LAB', 'OPERATOR', 'L2') THEN 'OPERATOR'
                        ELSE 'STAFF'
                    END
                """))
            else:
                conn.execute(text("UPDATE users SET role_code='STAFF' WHERE role_code IS NULL OR role_code=''"))

            if 'username' in user_cols:
                conn.execute(text("UPDATE users SET full_name=username WHERE full_name IS NULL OR full_name=''"))
            conn.execute(text("UPDATE users SET is_admin=FALSE WHERE is_admin IS NULL"))
            conn.execute(text("UPDATE users SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL"))

        if _table_exists(conn, 'projects'):
            _add_column(conn, 'projects', 'owner_id', 'INTEGER')
            _add_column(conn, 'projects', 'summary', 'TEXT')
            _add_column(conn, 'projects', 'is_hidden', 'BOOLEAN DEFAULT FALSE')
            _add_column(conn, 'projects', 'created_at', 'TIMESTAMP')
            _add_column(conn, 'projects', 'updated_at', 'TIMESTAMP')

            project_cols = _column_names(conn, 'projects')
            if 'creator_id' in project_cols:
                conn.execute(text("UPDATE projects SET owner_id=creator_id WHERE owner_id IS NULL"))
            if 'description' in project_cols:
                conn.execute(text("UPDATE projects SET summary=description WHERE summary IS NULL"))
            if 'status' in project_cols:
                conn.execute(text("UPDATE projects SET is_hidden=TRUE WHERE status='hidden'"))
            if 'secret_level' in project_cols:
                conn.execute(text("UPDATE projects SET is_hidden=TRUE WHERE secret_level >= 2"))

            conn.execute(text("""
                UPDATE projects
                SET owner_id = (
                    SELECT id FROM users ORDER BY id ASC LIMIT 1
                )
                WHERE owner_id IS NULL
            """))
            conn.execute(text("UPDATE projects SET summary='' WHERE summary IS NULL"))
            conn.execute(text("UPDATE projects SET is_hidden=FALSE WHERE is_hidden IS NULL"))
            conn.execute(text("UPDATE projects SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL"))
            conn.execute(text("UPDATE projects SET updated_at=created_at WHERE updated_at IS NULL"))

        if _table_exists(conn, 'project_files'):
            _add_column(conn, 'project_files', 'content_b64', 'TEXT')
            _add_column(conn, 'project_files', 'content_encoding', "VARCHAR(16) DEFAULT 'plain'")
            file_cols = _column_names(conn, 'project_files')
            if 'content_b64' in file_cols:
                if 'content' in file_cols:
                    conn.execute(text("UPDATE project_files SET content_b64=content WHERE (content_b64 IS NULL OR content_b64='')"))
                rows = conn.execute(text("SELECT id, filename FROM project_files")).fetchall()
                for row in rows:
                    fid = int(row[0])
                    name = row[1] or f'file_{fid}.txt'
                    payload = encode_text(f'FILE::{name}')
                    conn.execute(
                        text("UPDATE project_files SET content_b64=:payload WHERE id=:fid AND (content_b64 IS NULL OR content_b64='')"),
                        {'payload': payload, 'fid': fid},
                    )
            if 'content_encoding' in file_cols:
                conn.execute(text("UPDATE project_files SET content_encoding='plain' WHERE content_encoding IS NULL OR content_encoding=''"))

        if _table_exists(conn, 'project_notes'):
            _add_column(conn, 'project_notes', 'body_b64', 'TEXT')
            _add_column(conn, 'project_notes', 'body_encoding', "VARCHAR(16) DEFAULT 'plain'")
            note_cols = _column_names(conn, 'project_notes')
            if 'body_b64' in note_cols:
                if 'body' in note_cols:
                    conn.execute(text("UPDATE project_notes SET body_b64=body WHERE (body_b64 IS NULL OR body_b64='')"))
                conn.execute(text("UPDATE project_notes SET body_b64='' WHERE body_b64 IS NULL"))
            if 'body_encoding' in note_cols:
                conn.execute(text("UPDATE project_notes SET body_encoding='plain' WHERE body_encoding IS NULL OR body_encoding=''"))

        tx.commit()
    except Exception:
        tx.rollback()
        raise
    finally:
        conn.close()


def ensure_settings():
    if not get_setting('service_profile_json'):
        set_setting('service_profile_json', json.dumps({
            'service': 'Предприятие 3826',
            'mode': 'operations',
            'language': 'ru',
            'created_at': datetime.utcnow().isoformat(),
        }, ensure_ascii=False))


def seed_demo():
    if User.query.first():
        ensure_settings()
        db.session.commit()
        return

    ensure_settings()

    admin_password = os.getenv('ADMIN_PASSWORD', random_token(14))
    admin = User(
        username='sysadmin',
        email='sysadmin@cybernet.local',
        full_name='Системный администратор',
        role_code=ROLE_EXEC,
        is_admin=True,
    )
    admin.set_password(admin_password)
    db.session.add(admin)

    channels_data = [
        ('Орбита', 'Транспорт'),
        ('Полимер', 'Материалы'),
        ('Каскад', 'Энергетика'),
        ('Сигма', 'Складские контуры'),
        ('Квант', 'Расчётные узлы'),
        ('Маяк', 'Сервисные поставки'),
        ('Фрактал', 'Системная интеграция'),
        ('Вега', 'Резервные мощности'),
    ]
    channels = []
    for name, sector in channels_data:
        ch = PartnerChannel(name=name, sector=sector)
        db.session.add(ch)
        channels.append(ch)

    demo_specs = [
        ('staff_a', ROLE_STAFF),
        ('staff_b', ROLE_STAFF),
        ('staff_c', ROLE_STAFF),
        ('op_a', ROLE_OPERATOR),
        ('op_b', ROLE_OPERATOR),
        ('lead_a', ROLE_LEAD),
        ('lead_b', ROLE_LEAD),
        ('exec_a', ROLE_EXEC),
    ]
    demo_users = []
    for uname, role in demo_specs:
        suffix = random_token(5).lower()
        user = User(
            username=f'{uname}_{suffix}',
            email=f'{uname}_{suffix}@cybernet.local',
            full_name=f'Пользователь {uname.upper()}',
            role_code=role,
            is_admin=False,
        )
        user.set_password(random_token(24))
        db.session.add(user)
        demo_users.append(user)

    db.session.flush()

    owners = [admin] + demo_users
    project_titles = [
        'Контур поставок',
        'Резервный шлюз',
        'Карта зависимостей',
        'Граф транспортных узлов',
        'Модуль сверки партнёров',
        'План стабилизации',
        'Архив испытаний',
        'Сетка распределения',
        'Контроль инцидентов',
        'Пакет согласований',
    ]
    for idx in range(24):
        owner = secrets.choice(owners)
        project = Project(
            title=f'{secrets.choice(project_titles)} #{100 + idx}',
            summary='Служебный проект внутреннего контура предприятия.',
            is_hidden=(idx % 3 == 0),
            owner_id=owner.id,
        )
        db.session.add(project)
        db.session.flush()

        note_plain = f'Служебная заметка для проекта {project.id}'
        db.session.add(ProjectNote(
            project_id=project.id,
            author_id=owner.id,
            title='Техническая запись',
            body_b64=note_plain,
            body_encoding='plain',
        ))
        db.session.add(ProjectFile(
            project_id=project.id,
            uploader_id=owner.id,
            filename=f'brief_{project.id}.txt',
            content_b64=f'Внутренний бриф проекта {project.id}',
            content_encoding='plain',
        ))

        if project.is_hidden:
            ch = secrets.choice(channels)
            db.session.add(ProjectInvite(
                project_id=project.id,
                channel_id=ch.id,
                recipient_email=f'partner{idx}@vendor.local',
                invite_code=generate_invite_code(project.id, ch.id),
                status='pending',
            ))

    db.session.commit()


@app.context_processor
def inject_runtime():
    return {
        'role_labels': ROLE_LABELS,
        'csrf_token': csrf_token,
    }


@app.before_request
def enforce_csrf_for_forms():
    if request.method == 'POST' and not request.path.startswith('/api/'):
        validate_csrf()


@app.route('/api/health')
def api_health():
    return jsonify({'status': 'OK', 'timestamp': datetime.utcnow().isoformat()})


@app.route('/api/status')
@login_required
def api_status():
    if not current_user.is_authenticated or current_user.role_code != ROLE_EXEC:
        abort(403)
    return jsonify({
        'users': User.query.count(),
        'projects': Project.query.count(),
        'hidden_projects': Project.query.filter_by(is_hidden=True).count(),
        'channels': PartnerChannel.query.count(),
    })


@app.route('/')
def index():
    projects = Project.query.filter_by(is_hidden=False).order_by(Project.updated_at.desc()).limit(12).all()
    return render_template('index.html', projects=projects)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        require_rate_limit('register', get_client_ip(), limit=5, window_seconds=300)
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not email or not full_name or not password:
            log_event('auth.register', status='failed', details={'reason': 'validation'})
            flash('Заполните все поля', 'danger')
            return render_template('auth/register.html')
        if len(password) < 12 or len(username) > 64 or len(email) > 128 or len(full_name) > 128:
            log_event('auth.register', status='failed', details={'reason': 'validation_limits'})
            flash('Проверьте длину полей и используйте пароль не короче 12 символов', 'danger')
            return render_template('auth/register.html')
        if User.query.filter_by(username=username).first():
            log_event('auth.register', status='failed', details={'reason': 'username_exists', 'username': username})
            flash('Логин уже занят', 'danger')
            return render_template('auth/register.html')
        if User.query.filter_by(email=email).first():
            log_event('auth.register', status='failed', details={'reason': 'email_exists', 'email': email})
            flash('Email уже используется', 'danger')
            return render_template('auth/register.html')

        user = User(
            username=username,
            email=email,
            full_name=full_name,
            role_code=ROLE_STAFF,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        log_event('auth.register', details={'username': username})
        flash('Аккаунт создан. Выполните вход.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        require_rate_limit('login', f'{get_client_ip()}:{username}', limit=8, window_seconds=300)
        password = request.form.get('password', '').strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            log_event('auth.login.success', details={'username': username}, username=username)
            flash('Добро пожаловать', 'success')
            return redirect(url_for('dashboard'))
        log_event('auth.login.failed', status='failed', details={'username': username}, username=username or 'anonymous')
        flash('Неверные учетные данные', 'danger')
    return render_template('auth/login.html')


@app.route('/logout')
@login_required
def logout():
    log_event('auth.logout')
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    own_projects = Project.query.filter_by(owner_id=current_user.id).count()
    granted_projects = ProjectGrant.query.filter_by(user_id=current_user.id).count()
    hidden_visible = len([p for p in visible_projects_query(current_user).limit(100).all() if p.is_hidden])
    return render_template(
        'auth/dashboard.html',
        own_projects=own_projects,
        granted_projects=granted_projects,
        hidden_visible=hidden_visible,
    )


@app.route('/projects')
def projects_list():
    search = request.args.get('search', '').strip()
    rows = visible_projects_query(current_user)
    if search:
        rows = rows.filter((Project.title.ilike(f'%{search}%')) | (Project.summary.ilike(f'%{search}%')))
    projects = rows.limit(200).all()
    return render_template('projects/list.html', projects=projects, search=search)


@app.route('/projects/hidden')
@login_required
def hidden_projects():
    if current_user.role_code != ROLE_EXEC:
        abort(403)
    log_event('project.hidden.list')
    projects = Project.query.filter_by(is_hidden=True).order_by(Project.updated_at.desc()).all()
    return render_template('projects/hidden.html', projects=projects)


@app.route('/project/create', methods=['GET', 'POST'])
@login_required
def project_create():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        summary = request.form.get('summary', '').strip()
        is_hidden = request.form.get('is_hidden') == 'on'

        if len(title) > 180 or len(summary) > 4000:
            flash('Превышена допустимая длина полей', 'danger')
            return render_template('projects/create.html')
        if not title:
            flash('Название обязательно', 'danger')
            return render_template('projects/create.html')

        project = Project(
            title=title,
            summary=summary,
            is_hidden=is_hidden,
            owner_id=current_user.id,
        )
        db.session.add(project)
        db.session.commit()
        log_event('project.create', details={'project_id': project.id, 'is_hidden': is_hidden})
        flash('Проект создан', 'success')
        return redirect(url_for('project_detail', project_id=project.id))

    return render_template('projects/create.html')


@app.route('/project/<int:project_id>')
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_view_project(current_user, project):
        abort(404)
    log_event('project.view', details={'project_id': project.id, 'hidden': project.is_hidden})

    notes = ProjectNote.query.filter_by(project_id=project.id).order_by(ProjectNote.created_at.desc()).all()
    files = ProjectFile.query.filter_by(project_id=project.id).order_by(ProjectFile.created_at.desc()).all()
    if can_manage_project(current_user, project):
        invites = ProjectInvite.query.filter_by(project_id=project.id).order_by(ProjectInvite.created_at.desc()).all()
        grants = ProjectGrant.query.filter_by(project_id=project.id).order_by(ProjectGrant.created_at.desc()).all()
    else:
        invites = []
        grants = []
    channels = PartnerChannel.query.order_by(PartnerChannel.id.asc()).all()

    decoded_notes = []
    for note in notes:
        decoded_notes.append({
            'id': note.id,
            'title': note.title,
            'body_text': note.body_b64 or '',
            'author': note.author.username,
            'created_at': note.created_at,
        })

    decoded_files = []
    for f in files:
        decoded_files.append({
            'id': f.id,
            'filename': f.filename,
            'content_text': f.content_b64 or '',
            'uploader': f.uploader.username,
            'created_at': f.created_at,
        })

    return render_template(
        'projects/detail.html',
        project=project,
        notes=decoded_notes,
        files=decoded_files,
        invites=invites,
        grants=grants,
        channels=channels,
        can_manage=can_manage_project(current_user, project),
    )


@app.route('/project/<int:project_id>/note', methods=['POST'])
@login_required
def project_add_note(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(current_user, project):
        abort(403)

    title = request.form.get('title', '').strip() or 'Служебная заметка'
    body = request.form.get('body', '').strip()
    if len(title) > 180 or len(body) > 64000:
        flash('Превышена допустимая длина заметки', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))
    if not body:
        flash('Текст заметки пустой', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))

    note = ProjectNote(
        project_id=project.id,
        author_id=current_user.id,
        title=title,
        body_b64=body,
        body_encoding='plain',
    )
    db.session.add(note)
    db.session.commit()
    log_event('project.note.create', details={'project_id': project.id, 'note_id': note.id})
    flash('Заметка добавлена', 'success')
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/project/<int:project_id>/file', methods=['POST'])
@login_required
def project_add_file(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(current_user, project):
        abort(403)

    filename = request.form.get('filename', '').strip() or f'payload_{random_token(6)}.txt'
    content = request.form.get('content', '').strip()
    if len(filename) > 180 or len(content) > 64000:
        flash('Превышена допустимая длина файла', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))
    if not content:
        flash('Содержимое файла пустое', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))

    row = ProjectFile(
        project_id=project.id,
        uploader_id=current_user.id,
        filename=filename,
        content_b64=content,
        content_encoding='plain',
    )
    db.session.add(row)
    db.session.commit()
    log_event('project.file.create', details={'project_id': project.id, 'file_id': row.id, 'filename': row.filename})
    flash('Файл добавлен', 'success')
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/project/<int:project_id>/invite', methods=['POST'])
@login_required
def project_create_invite(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(current_user, project):
        abort(403)

    recipient_email = request.form.get('recipient_email', '').strip().lower()
    channel_id = request.form.get('channel_id', type=int)
    channel = PartnerChannel.query.get(channel_id) if channel_id else None

    if len(recipient_email) > 180 or not recipient_email or not channel:
        flash('Укажите email и канал', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))

    invite = ProjectInvite(
        project_id=project.id,
        channel_id=channel.id,
        recipient_email=recipient_email,
        invite_code=generate_invite_code(project.id, channel.id),
        status='pending',
    )
    db.session.add(invite)
    db.session.commit()
    log_event('invite.create', details={'project_id': project.id, 'invite_id': invite.id, 'channel_id': channel.id})
    flash('Партнёрское приглашение зарегистрировано', 'success')
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/invites/accept', methods=['POST'])
@login_required
def invites_accept():
    require_rate_limit('invite_accept', f'{get_client_ip()}:{current_user.id}', limit=10, window_seconds=300)
    invite_code = request.form.get('invite_code', '').strip()

    invite = ProjectInvite.query.filter(
        ProjectInvite.invite_code == invite_code,
        ProjectInvite.status == 'pending',
    ).first()
    if not invite:
        log_event('invite.accept', status='failed', details={'reason': 'invalid_code'})
        flash('Код не найден или уже использован', 'danger')
        return redirect(url_for('projects_list'))

    if invite.recipient_email.lower() != current_user.email.lower() and current_user.role_code != ROLE_EXEC:
        log_event('invite.accept', status='failed', details={'reason': 'recipient_mismatch', 'invite_id': invite.id})
        abort(403)

    granted_count = 0
    if add_project_grant_if_missing(current_user.id, invite.project_id, 'partner_invite'):
        granted_count += 1

    invite.status = 'accepted'
    db.session.commit()
    log_event('invite.accept', details={'project_id': invite.project_id, 'invite_id': invite.id, 'granted_count': granted_count})
    flash(f'Доступ к проекту активирован. Выдано доступов: {granted_count}', 'success')
    return redirect(url_for('project_detail', project_id=invite.project_id))


@app.route('/partners')
@login_required
def partners():
    channels = PartnerChannel.query.order_by(PartnerChannel.id.asc()).all()
    return render_template('auth/partners.html', channels=channels)


@app.route('/partners/channel/<int:channel_id>/feed')
@login_required
def partners_feed(channel_id):
    channel = PartnerChannel.query.get_or_404(channel_id)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip().lower()
    page = max(request.args.get('page', 1, type=int) or 1, 1)
    per_page = 12

    query = ProjectInvite.query.join(Project, ProjectInvite.project_id == Project.id).filter(
        ProjectInvite.channel_id == channel.id,
    )
    if search:
        like_value = f'%{search}%'
        query = query.filter(
            (Project.title.ilike(like_value)) |
            (Project.summary.ilike(like_value)) |
            (ProjectInvite.recipient_email.ilike(like_value)) |
            (ProjectInvite.invite_code.ilike(like_value))
        )
    if status_filter in {'pending', 'accepted'}:
        query = query.filter(ProjectInvite.status == status_filter)

    total = query.count()
    pages = max((total + per_page - 1) // per_page, 1)
    if page > pages:
        page = pages
    rows = (
        query
        .order_by(ProjectInvite.created_at.desc(), ProjectInvite.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    feed = []
    for idx, item in enumerate(rows):
        can_see_project = can_manage_project(current_user, item.project)
        display_index = (page - 1) * per_page + idx + 1
        feed.append({
            'display_id': f'#{item.id}' if can_see_project else f'строка {display_index}',
            'statement_ref': case_ref('INV', item.id) if can_see_project else 'закрыто',
            'statement_url': url_for('partner_invite_statement', statement_ref=case_ref('INV', item.id)) if can_see_project else '',
            'project_name': item.project.title if can_see_project else 'Закрытый контур',
            'invite_code': item.invite_code if can_see_project else f'{item.invite_code[:4]}••••',
            'recipient_email': item.recipient_email if can_see_project else 'masked',
            'status': item.status,
            'created_at': item.created_at,
            'is_redacted': not can_see_project,
        })

    return render_template(
        'auth/partners_feed.html',
        channel=channel,
        feed=feed,
        search=search,
        status_filter=status_filter,
        total=total,
        page=page,
        pages=pages,
    )


@app.route('/partners/invites/<statement_ref>/statement')
@login_required
def partner_invite_statement(statement_ref):
    invite_id = parse_case_ref(statement_ref, 'INV')
    if not invite_id:
        abort(404)
    invite = ProjectInvite.query.get_or_404(invite_id)
    project = Project.query.get_or_404(invite.project_id)
    if not can_manage_project(current_user, project):
        abort(403)
    log_event('invite.statement.view', details={'invite_id': invite.id, 'project_id': project.id})
    payload = {
        'statement_ref': case_ref('INV', invite.id),
        'channel_id': invite.channel_id,
        'channel': invite.channel.name,
        'project_id': project.id,
        'project_title': project.title,
        'invite_code': invite.invite_code,
        'recipient_email': invite.recipient_email,
        'status': invite.status,
        'created_at': invite.created_at.isoformat(),
    }
    if request.args.get('format') == 'json':
        return jsonify(payload)
    return render_template('auth/partner_statement.html', statement=payload)


@app.route('/notebook', methods=['GET', 'POST'])
@login_required
def notebook():
    if request.method == 'POST' and request.form.get('action') == 'create':
        title = request.form.get('title', '').strip() or 'Запись'
        body = request.form.get('body', '').strip()
        if len(title) > 180 or len(body) > 64000:
            flash('Превышена допустимая длина записи', 'danger')
            return redirect(url_for('notebook'))
        if not body:
            flash('Текст записи не может быть пустым', 'danger')
            return redirect(url_for('notebook'))
        row = NotebookEntry(user_id=current_user.id, title=title, body=body)
        db.session.add(row)
        db.session.commit()
        log_event('notebook.create', details={'entry_id': row.id})
        flash('Запись сохранена', 'success')
        return redirect(url_for('notebook'))

    q = request.values.get('q', '').strip()
    rows, _ = search_notebook(current_user.id, q)
    return render_template('auth/notebook.html', entries=rows, q=q)


@app.route('/account/recovery', methods=['GET', 'POST'])
def recovery_page():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        require_rate_limit('recovery_request', f'{get_client_ip()}:{username}', limit=5, window_seconds=300)
        user = User.query.filter_by(username=username).first()
        if user:
            ticket = RecoveryTicket(
                user_id=user.id,
                token=random_token(28),
                status='approved',
                expires_at=datetime.utcnow() + timedelta(minutes=45),
            )
            db.session.add(ticket)
            db.session.commit()
            log_event('recovery.request', details={'target_user': username, 'ticket_id': ticket.id}, username='anonymous')
        else:
            log_event('recovery.request', status='failed', details={'target_user': username, 'reason': 'unknown_user'}, username='anonymous')
        flash('Запрос обработан. Используйте форму подтверждения.', 'info')
        return redirect(url_for('recovery_page'))

    own_tickets = []
    if current_user.is_authenticated:
        own_tickets = (
            RecoveryTicket.query
            .filter_by(user_id=current_user.id)
            .order_by(RecoveryTicket.created_at.desc())
            .limit(10)
            .all()
        )
    return render_template('auth/recovery.html', own_tickets=own_tickets)


@app.route('/account/recovery/audit')
@login_required
def recovery_audit():
    if current_user.role_code != ROLE_EXEC:
        abort(403)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip().lower()
    query = RecoveryTicket.query.join(User, RecoveryTicket.user_id == User.id)

    if search:
        pattern = f'%{search}%'
        query = query.filter(
            (User.username.ilike(pattern)) |
            (User.email.ilike(pattern)) |
            (User.full_name.ilike(pattern))
        )
    if status_filter in {'approved', 'used', 'expired'}:
        query = query.filter(RecoveryTicket.status == status_filter)

    latest = query.order_by(RecoveryTicket.created_at.desc(), RecoveryTicket.id.desc()).first()
    log_event('recovery.audit.view', details={'search': search, 'status_filter': status_filter, 'total': query.count()})
    return jsonify({
        'total': query.count(),
        'latest_case_ref': case_ref('REC', latest.id) if latest else None,
        'latest_status': latest.status if latest else None,
        'search': search,
        'status': status_filter,
    })


@app.route('/account/recovery/cases/<case_reference>/statement')
@login_required
def recovery_case_statement(case_reference):
    ticket_id = parse_case_ref(case_reference, 'REC')
    if not ticket_id:
        abort(404)
    ticket = RecoveryTicket.query.get_or_404(ticket_id)
    if ticket.user_id != current_user.id and current_user.role_code != ROLE_EXEC:
        abort(403)
    user = User.query.get_or_404(ticket.user_id)
    log_event('recovery.statement.view', details={'case_ref': case_ref('REC', ticket.id), 'target_user': user.username})
    payload = {
        'case_ref': case_ref('REC', ticket.id),
        'username': user.username,
        'account_id': user.id,
        'status': ticket.status,
        'created_at': ticket.created_at.isoformat(),
        'expires_at': ticket.expires_at.isoformat(),
    }
    if request.args.get('format') == 'json':
        return jsonify(payload)
    return render_template('auth/recovery_statement.html', statement=payload)


@app.route('/account/recovery/confirm', methods=['POST'])
def recovery_confirm():
    username = request.form.get('username', '').strip()
    require_rate_limit('recovery_confirm', f'{get_client_ip()}:{username}', limit=5, window_seconds=300)
    case_reference = request.form.get('case_ref', '').strip()
    ticket_id = parse_case_ref(case_reference, 'REC')
    resolution_code = request.form.get('resolution_code', '').strip()
    new_password = request.form.get('new_password', '').strip()

    if not username or not ticket_id or not resolution_code or not new_password or len(new_password) < 12:
        log_event('recovery.confirm', status='failed', details={'reason': 'validation'})
        flash('Заполните все поля подтверждения и используйте пароль не короче 12 символов', 'danger')
        return redirect(url_for('recovery_page'))

    ticket = RecoveryTicket.query.filter_by(id=ticket_id, token=resolution_code, status='approved').first()
    user = User.query.filter_by(username=username).first()

    if not ticket or ticket.expires_at < datetime.utcnow() or not user or ticket.user_id != user.id:
        log_event('recovery.confirm', status='failed', details={'username': username, 'reason': 'invalid_ticket'})
        flash('Подтверждение отклонено', 'danger')
        return redirect(url_for('recovery_page'))

    user.set_password(new_password)
    ticket.status = 'used'
    db.session.commit()
    log_event('recovery.confirm', details={'username': username, 'ticket_id': ticket.id})
    flash('Пароль обновлён', 'success')
    return redirect(url_for('login'))


@app.route('/handbook')
@login_required
def handbook():
    return render_template('auth/handbook.html')


@app.route('/api/me')
@login_required
def api_me():
    log_event('session.me')
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'role_code': current_user.role_code,
        'role_label': current_user.role_label,
    })


@app.route('/api/projects', methods=['POST'])
@login_required
def api_projects_create():
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    summary = (data.get('summary') or '').strip()
    is_hidden = bool(data.get('is_hidden', True))

    if len(title) > 180 or len(summary) > 4000:
        return jsonify({'error': 'field too large'}), 413
    if not title:
        return jsonify({'error': 'title is required'}), 400

    project = Project(title=title, summary=summary, is_hidden=is_hidden, owner_id=current_user.id)
    db.session.add(project)
    db.session.commit()
    log_event('project.create', details={'project_id': project.id, 'is_hidden': is_hidden, 'via': 'api'})
    return jsonify({'project_id': project.id}), 201


@app.route('/api/projects/<int:project_id>')
@login_required
def api_project_get(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_view_project(current_user, project):
        return jsonify({'error': 'not found'}), 404
    log_event('project.view', details={'project_id': project.id, 'hidden': project.is_hidden, 'via': 'api'})

    return jsonify({
        'id': project.id,
        'title': project.title,
        'summary': project.summary,
        'is_hidden': project.is_hidden,
        'owner_id': project.owner_id,
        'note_count': ProjectNote.query.filter_by(project_id=project.id).count(),
        'file_count': ProjectFile.query.filter_by(project_id=project.id).count(),
    })


@app.route('/api/projects/<int:project_id>/notes', methods=['POST'])
@login_required
def api_project_note_create(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(current_user, project):
        return jsonify({'error': 'forbidden'}), 403

    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip() or 'Secret Note'
    body = (data.get('body') or data.get('body_b64') or '').strip()

    if len(title) > 180 or len(body) > 64000:
        return jsonify({'error': 'field too large'}), 413
    if not body:
        return jsonify({'error': 'body is required'}), 400

    note = ProjectNote(
        project_id=project.id,
        author_id=current_user.id,
        title=title,
        body_b64=body,
        body_encoding='plain',
    )
    db.session.add(note)
    db.session.commit()
    log_event('project.note.create', details={'project_id': project.id, 'note_id': note.id, 'via': 'api'})
    return jsonify({'note_id': note.id}), 201


@app.route('/api/project-notes/<int:note_id>')
@login_required
def api_project_note_get(note_id):
    note = ProjectNote.query.get_or_404(note_id)
    project = Project.query.get_or_404(note.project_id)
    if not can_view_project(current_user, project):
        return jsonify({'error': 'not found'}), 404
    log_event('project.note.view', details={'project_id': project.id, 'note_id': note.id})
    return jsonify({
        'id': note.id,
        'project_id': note.project_id,
        'title': note.title,
        'body': note.body_b64,
    })


@app.route('/api/projects/<int:project_id>/files', methods=['POST'])
@login_required
def api_project_file_create(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(current_user, project):
        return jsonify({'error': 'forbidden'}), 403

    data = request.get_json(silent=True) or {}
    filename = (data.get('filename') or '').strip() or f'payload_{random_token(6)}.txt'
    content = (data.get('content') or data.get('content_b64') or '').strip()

    if len(filename) > 180 or len(content) > 64000:
        return jsonify({'error': 'field too large'}), 413
    if not content:
        return jsonify({'error': 'content is required'}), 400

    row = ProjectFile(
        project_id=project.id,
        uploader_id=current_user.id,
        filename=filename,
        content_b64=content,
        content_encoding='plain',
    )
    db.session.add(row)
    db.session.commit()
    log_event('project.file.create', details={'project_id': project.id, 'file_id': row.id, 'filename': row.filename, 'via': 'api'})
    return jsonify({'file_id': row.id}), 201


@app.route('/api/project-files/<int:file_id>')
@login_required
def api_project_file_get(file_id):
    row = ProjectFile.query.get_or_404(file_id)
    project = Project.query.get_or_404(row.project_id)
    if not can_view_project(current_user, project):
        return jsonify({'error': 'not found'}), 404
    log_event('project.file.view', details={'project_id': project.id, 'file_id': row.id, 'filename': row.filename})
    return jsonify({
        'id': row.id,
        'project_id': row.project_id,
        'filename': row.filename,
        'content': row.content_b64,
    })


@app.route('/api/projects/<int:project_id>/invites', methods=['POST'])
@login_required
def api_project_invite_create(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(current_user, project):
        return jsonify({'error': 'forbidden'}), 403

    data = request.get_json(silent=True) or {}
    recipient_email = (data.get('recipient_email') or '').strip().lower()
    channel_id = int(data.get('channel_id') or 0)
    channel = PartnerChannel.query.get(channel_id)

    if len(recipient_email) > 180 or not recipient_email or not channel:
        return jsonify({'error': 'recipient_email and channel_id required'}), 400

    invite = ProjectInvite(
        project_id=project.id,
        channel_id=channel.id,
        recipient_email=recipient_email,
        invite_code=generate_invite_code(project.id, channel.id),
        status='pending',
    )
    db.session.add(invite)
    db.session.commit()
    log_event('invite.create', details={'project_id': project.id, 'invite_id': invite.id, 'channel_id': channel.id, 'via': 'api'})
    return jsonify({'invite_id': invite.id, 'invite_code': invite.invite_code}), 201


@app.route('/api/channels')
@login_required
def api_channels():
    rows = PartnerChannel.query.order_by(PartnerChannel.id.asc()).all()
    log_event('channel.list', details={'count': len(rows)})
    return jsonify([{'id': r.id, 'name': r.name, 'sector': r.sector} for r in rows])


@app.route('/account/recovery/cases')
@login_required
def api_recovery_tickets():
    rows = RecoveryTicket.query.filter_by(user_id=current_user.id).order_by(RecoveryTicket.created_at.desc()).limit(20).all()
    log_event('recovery.case.list', details={'count': len(rows)})
    return jsonify([
        {
            'id': r.id,
            'case_ref': case_ref('REC', r.id),
            'status': r.status,
            'expires_at': r.expires_at.isoformat(),
        }
        for r in rows
    ])


@app.errorhandler(403)
def handle_403(_):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def handle_404(_):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def handle_500(_):
    db.session.rollback()
    return render_template('errors/500.html'), 500


with app.app_context():
    run_schema_migrations()
    db.create_all()
    run_schema_migrations()
    seed_demo()


if __name__ == '__main__':
    host = os.getenv('SERVER_HOST', '0.0.0.0')
    port = int(os.getenv('SERVER_PORT', '5050'))
    app.run(host=host, port=port, debug=False)
