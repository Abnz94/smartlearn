import os, uuid, json, hashlib, secrets, datetime, re, smtplib, sqlite3
import urllib.request, urllib.error, ssl, certifi
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False

load_dotenv()

app = Flask(__name__, static_folder='.', static_url_path='')
REDIS_URL = os.getenv('REDIS_URL', None)
if REDIS_URL:
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[], storage_uri=REDIS_URL)
else:
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])

ADMIN_EMAIL          = os.getenv('ADMIN_EMAIL', '').strip().lower()
ADMIN_PASSWORD       = os.getenv('ADMIN_PASSWORD', '').strip()
CLAUDE_API_KEY       = os.getenv('API_KEY', '').strip()
SMTP_HOST            = 'smtp.gmail.com'
SMTP_PORT            = 587
SMTP_USER            = os.getenv('SMTP_USER', ADMIN_EMAIL)
SMTP_PASSWORD        = os.getenv('SMTP_PASSWORD', '')
STRIPE_SECRET_KEY    = os.getenv('STRIPE_SECRET_KEY', '')
STRIPE_WEBHOOK_SECRET= os.getenv('STRIPE_WEBHOOK_SECRET', '')
STRIPE_PRICE_ID      = os.getenv('STRIPE_PRICE_ID', '')
APP_URL              = os.getenv('APP_URL', 'https://web-production-0036d.up.railway.app')

if STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

DB_FILE      = os.getenv('DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'smartlearn.db'))
# Crée le dossier parent si nécessaire (ex: /data sur Railway)
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
SESSION_DAYS = 30
EMAIL_RE     = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# ─── BASE DE DONNÉES ─────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

def init_db():
    with get_db() as c:
        c.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                email          TEXT PRIMARY KEY,
                name           TEXT NOT NULL,
                password       TEXT NOT NULL,
                plan           TEXT NOT NULL DEFAULT 'free',
                is_admin       INTEGER NOT NULL DEFAULT 0,
                xp             INTEGER NOT NULL DEFAULT 0,
                streak         INTEGER NOT NULL DEFAULT 0,
                games_played   INTEGER NOT NULL DEFAULT 0,
                correct_ans    INTEGER NOT NULL DEFAULT 0,
                total_ans      INTEGER NOT NULL DEFAULT 0,
                last_play_date TEXT NOT NULL DEFAULT '',
                achievements   TEXT NOT NULL DEFAULT '[]',
                api_key        TEXT NOT NULL DEFAULT '',
                daily_plays    TEXT NOT NULL DEFAULT '{}',
                credits        INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                email      TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
        ''')
        # Migration : ajoute la colonne credits si elle n'existe pas
        cols = [r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()]
        if 'credits' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN credits INTEGER NOT NULL DEFAULT 0")
        c.executescript('''
        ''')
        if ADMIN_EMAIL and ADMIN_PASSWORD:
            c.execute('''
                INSERT OR IGNORE INTO users (email, name, password, plan, is_admin)
                VALUES (?, 'Admin', ?, 'pro', 1)
            ''', (ADMIN_EMAIL, hash_password(ADMIN_PASSWORD)))
        c.commit()

# ─── SÉCURITÉ ────────────────────────────────────────────────────────────────

def hash_password(password):
    salt = secrets.token_hex(16)
    key  = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f'pbkdf2:{salt}:{key.hex()}'

def verify_password(password, stored):
    if not stored.startswith('pbkdf2:'):
        return password == stored  # migration transparente
    try:
        _, salt, key_hex = stored.split(':')
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return secrets.compare_digest(key.hex(), key_hex)
    except Exception:
        return False

# ─── SESSIONS ────────────────────────────────────────────────────────────────

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def create_session(email):
    token      = str(uuid.uuid4())
    expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=SESSION_DAYS)).isoformat()
    with get_db() as c:
        c.execute('DELETE FROM sessions WHERE expires_at < ?', (now_iso(),))
        c.execute('INSERT INTO sessions (token, email, expires_at) VALUES (?, ?, ?)',
                  (token, email, expires_at))
        c.commit()
    return token

def get_email_from_token(token):
    if not token:
        return None
    with get_db() as c:
        row = c.execute(
            'SELECT email FROM sessions WHERE token = ? AND expires_at > ?',
            (token, now_iso())
        ).fetchone()
    return row['email'] if row else None

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def safe_user(row):
    d = dict(row)
    d.pop('password', None)
    d.pop('api_key', None)
    d['isAdmin']        = bool(d.pop('is_admin', 0))
    d['gamesPlayed']    = d.pop('games_played', 0)
    d['correctAnswers'] = d.pop('correct_ans', 0)
    d['totalAnswers']   = d.pop('total_ans', 0)
    d['lastPlayDate']   = d.pop('last_play_date', '')
    d['achievements']   = json.loads(d.get('achievements') or '[]')
    d['dailyPlays']     = json.loads(d.pop('daily_plays') or '{}')
    d['credits']        = d.get('credits', 0)
    return d

def get_user(email):
    with get_db() as c:
        return c.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

# ─── EMAIL ───────────────────────────────────────────────────────────────────

def send_welcome_email(name, to_email):
    if not SMTP_PASSWORD:
        return
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Bienvenue sur SmartLearn !'
        msg['From']    = f'SmartLearn <{SMTP_USER}>'
        msg['To']      = to_email
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f0f0f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px">
<tr><td align="center"><table width="520" cellpadding="0" cellspacing="0"
  style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08)">
  <tr>
    <td style="background:linear-gradient(135deg,#6c63ff,#ff6584);padding:36px;text-align:center">
      <h1 style="margin:0;color:white;font-size:2rem;font-weight:800">SmartLearn</h1>
      <p style="margin:8px 0 0;color:rgba(255,255,255,0.85);font-size:0.9rem">Apprends mieux, plus vite</p>
    </td>
  </tr>
  <tr>
    <td style="padding:40px 36px">
      <h2 style="margin:0 0 16px;color:#1a1a2e;font-size:1.4rem">Bienvenue, {name} !</h2>
      <p style="color:#555;line-height:1.7;margin-bottom:16px">
        Ton compte SmartLearn est actif. Tu peux te connecter à tout moment avec ton adresse email.
      </p>
      <p style="color:#555;line-height:1.7;margin-bottom:8px">Ce que tu peux faire avec ton compte <strong>gratuit</strong> :</p>
      <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px">
        <tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#333">
          🎯 <strong>5 parties par jour</strong> — QCM, Vrai/Faux, Trous, Ordre</td></tr>
        <tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#333">
          📄 <strong>Upload de cours</strong> — photo ou PDF analysé par l'IA</td></tr>
        <tr><td style="padding:10px 0;color:#333">
          🏆 <strong>Badges et XP</strong> — suis ta progression</td></tr>
      </table>
      <p style="color:#888;font-size:0.85rem;margin:0">À bientôt sur SmartLearn !</p>
    </td>
  </tr>
  <tr>
    <td style="background:#f9f9f9;padding:18px 36px;text-align:center">
      <p style="margin:0;color:#bbb;font-size:0.75rem">SmartLearn · Ne pas répondre à cet email</p>
    </td>
  </tr>
</table></td></tr></table></body></html>"""
        msg.attach(MIMEText(html, 'html', 'utf-8'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(SMTP_USER, to_email, msg.as_string())
    except Exception as e:
        print(f'[Email] Erreur : {e}')

# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data     = request.get_json(silent=True) or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()
    name     = data.get('name', '').strip()

    if not email or not password or not name:
        return jsonify({'error': 'Champs manquants'}), 400
    if not EMAIL_RE.match(email):
        return jsonify({'error': 'Adresse email invalide'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Mot de passe trop court (6 caractères minimum)'}), 400
    if len(name) < 2:
        return jsonify({'error': 'Prénom trop court'}), 400

    with get_db() as c:
        if c.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone():
            return jsonify({'error': 'Email déjà utilisé'}), 400
        is_admin = 1 if (email == ADMIN_EMAIL and password == ADMIN_PASSWORD) else 0
        plan     = 'pro' if is_admin else 'free'
        c.execute(
            'INSERT INTO users (email, name, password, plan, is_admin) VALUES (?, ?, ?, ?, ?)',
            (email, name, hash_password(password), plan, is_admin)
        )
        c.commit()

    send_welcome_email(name, email)
    token = create_session(email)
    return jsonify({'success': True, 'user': safe_user(get_user(email)), 'token': token})

@app.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    data     = request.get_json(silent=True) or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not email or not password:
        return jsonify({'error': 'Champs manquants'}), 400

    row = get_user(email)
    if not row:
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    stored = dict(row)['password']

    # Migration transparente : ancien mot de passe en clair
    if not stored.startswith('pbkdf2:'):
        if password != stored:
            return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
        with get_db() as c:
            c.execute('UPDATE users SET password = ? WHERE email = ?',
                      (hash_password(password), email))
            c.commit()
    elif not verify_password(password, stored):
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    token = create_session(email)
    return jsonify({'success': True, 'user': safe_user(get_user(email)), 'token': token})

@app.route('/api/logout', methods=['POST'])
def logout():
    token = (request.get_json(silent=True) or {}).get('token', '')
    if token:
        with get_db() as c:
            c.execute('DELETE FROM sessions WHERE token = ?', (token,))
            c.commit()
    return jsonify({'success': True})

@app.route('/api/session', methods=['POST'])
def session():
    token = (request.get_json(silent=True) or {}).get('token', '')
    email = get_email_from_token(token)
    if not email:
        return jsonify({'error': 'Session invalide ou expirée'}), 401
    row = get_user(email)
    if not row:
        with get_db() as c:
            c.execute('DELETE FROM sessions WHERE token = ?', (token,))
            c.commit()
        return jsonify({'error': 'Utilisateur introuvable'}), 404
    return jsonify({'success': True, 'user': safe_user(row)})

@app.route('/api/claude', methods=['POST'])
def claude():
    data     = request.get_json(silent=True) or {}
    token    = data.get('token', '')
    messages = data.get('messages', [])

    api_key = CLAUDE_API_KEY
    if not api_key:
        return jsonify({'error': "Aucune clé API configurée. Ajoute API_KEY dans le fichier .env"}), 400

    # Vérification des crédits / plan
    email = get_email_from_token(token)
    if email:
        row = get_user(email)
        if row:
            u = dict(row)
            if not u['is_admin'] and u['plan'] != 'pro':
                credits = u.get('credits', 0)
                if credits <= 0:
                    return jsonify({'error': 'Vous n\'avez plus de crédits. Achetez un pack pour continuer !', 'no_credits': True}), 429
                with get_db() as c:
                    c.execute('UPDATE users SET credits = credits - 1 WHERE email = ?', (email,))
                    c.commit()

    payload = json.dumps({
        'model': 'claude-sonnet-4-6',
        'max_tokens': 2000,
        'messages': messages
    }).encode()
    req = urllib.request.Request(
        'https://api.anthropic.com/v1/messages',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
            'anthropic-beta': 'pdfs-2024-09-25'
        }
    )
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(req, context=ctx) as resp:
            result = json.loads(resp.read())
            return jsonify({'success': True, 'content': result['content'][0]['text']})
    except urllib.error.HTTPError as e:
        err = json.loads(e.read())
        return jsonify({'error': err.get('error', {}).get('message', 'Erreur API')}), e.code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users', methods=['POST'])
def admin_users():
    token = (request.get_json(silent=True) or {}).get('token', '')
    email = get_email_from_token(token)
    if not email or email != ADMIN_EMAIL:
        return jsonify({'error': 'Non autorisé'}), 403
    with get_db() as c:
        rows = c.execute('SELECT email, name, plan, games_played, xp FROM users').fetchall()
    return jsonify({'users': [
        {'email': r['email'], 'name': r['name'], 'plan': r['plan'],
         'gamesPlayed': r['games_played'], 'xp': r['xp']}
        for r in rows
    ]})

@app.route('/api/admin/set-pro', methods=['POST'])
def admin_set_pro():
    data   = request.get_json(silent=True) or {}
    token  = data.get('token', '')
    email  = get_email_from_token(token)
    if not email or email != ADMIN_EMAIL:
        return jsonify({'error': 'Non autorisé'}), 403
    target = data.get('targetEmail', '').strip().lower()
    plan   = data.get('plan', 'pro')
    with get_db() as c:
        if not c.execute('SELECT 1 FROM users WHERE email = ?', (target,)).fetchone():
            return jsonify({'error': 'Utilisateur introuvable'}), 404
        c.execute('UPDATE users SET plan = ? WHERE email = ?', (plan, target))
        c.commit()
    return jsonify({'success': True})

@app.route('/api/update-stats', methods=['POST'])
def update_stats():
    data  = request.get_json(silent=True) or {}
    token = data.get('token', '')
    email = get_email_from_token(token)
    if not email:
        return jsonify({'error': 'Non autorisé'}), 401
    with get_db() as c:
        if not c.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone():
            return jsonify({'error': 'Utilisateur introuvable'}), 404
        c.execute('''
            UPDATE users SET
                xp = ?, streak = ?, games_played = ?, correct_ans = ?,
                total_ans = ?, last_play_date = ?, achievements = ?
            WHERE email = ?
        ''', (
            data.get('xp', 0),
            data.get('streak', 0),
            data.get('gamesPlayed', 0),
            data.get('correctAnswers', 0),
            data.get('totalAnswers', 0),
            data.get('lastPlayDate', ''),
            json.dumps(data.get('achievements', [])),
            email
        ))
        c.commit()
    return jsonify({'success': True})


# ─── STRIPE ──────────────────────────────────────────────────────────────────

@app.route('/api/create-checkout', methods=['POST'])
def create_checkout():
    if not STRIPE_AVAILABLE or not STRIPE_SECRET_KEY:
        return jsonify({'error': 'Stripe non configuré'}), 503
    data  = request.get_json(silent=True) or {}
    token = data.get('token', '')
    email = get_email_from_token(token)
    if not email:
        return jsonify({'error': 'Non autorisé'}), 401
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price': STRIPE_PRICE_ID, 'quantity': 1}],
            mode='payment',
            success_url=f'{APP_URL}?payment=success',
            cancel_url=f'{APP_URL}?payment=cancel',
            customer_email=email,
            metadata={'email': email}
        )
        return jsonify({'url': session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stripe-webhook', methods=['POST'])
def stripe_webhook():
    if not STRIPE_AVAILABLE:
        return jsonify({'error': 'Stripe non disponible'}), 503
    payload = request.get_data()
    sig     = request.headers.get('Stripe-Signature', '')
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        email   = session.get('metadata', {}).get('email') or session.get('customer_email', '')
        if email:
            with get_db() as c:
                c.execute('UPDATE users SET credits = credits + 3 WHERE email = ?', (email.lower(),))
                c.commit()
    return jsonify({'received': True})

@app.route('/api/credits', methods=['POST'])
def get_credits():
    token = (request.get_json(silent=True) or {}).get('token', '')
    email = get_email_from_token(token)
    if not email:
        return jsonify({'error': 'Non autorisé'}), 401
    row = get_user(email)
    if not row:
        return jsonify({'error': 'Utilisateur introuvable'}), 404
    return jsonify({'credits': dict(row).get('credits', 0), 'plan': dict(row)['plan']})


# ─── DÉMARRAGE ───────────────────────────────────────────────────────────────

# Initialise la DB au démarrage (fonctionne avec gunicorn ET python directement)
init_db()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    print('=' * 50)
    print('  SmartLearn — Serveur Flask')
    print(f'  http://localhost:{port}')
    print('=' * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
