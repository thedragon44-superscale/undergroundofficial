import os
import json
import threading
import asyncio
import bcrypt
import secrets
import time
import requests
from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
from werkzeug.utils import secure_filename
import websockets
from dotenv import load_dotenv

# --- PLATFORM INFRASTRUCTURE DRIVERS ---
import psycopg2
from psycopg2.extras import RealDictCursor
import boto3
import stripe

load_dotenv()

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

FLASK_KEY = os.getenv("FLASK_SECRET_KEY", "fallback_temporary_flask_key")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_placeholder_key")
NEON_URL = os.getenv("NEON_DATABASE_URL") or os.getenv("DATABASE_URL")

# Apply secret authorization credentials to the Stripe layer
stripe.api_key = STRIPE_SECRET_KEY

# AWS Storage Configuration Context
AWS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_BUCKET = os.getenv("AWS_STORAGE_BUCKET_NAME")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

DEFAULT_AVATAR_CDN = "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&q=80&w=150"

# --- BITCOIN LIGHTNING STRUCTURAL DRIVERS ---
LNBITS_URL = os.getenv("LNBITS_URL", "https://demo.lnbits.com")
LNBITS_MASTER_KEY = os.getenv("LNBITS_MASTER_KEY", "")

app = Flask(__name__, template_folder='templates')
app.secret_key = FLASK_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

CONNECTED_CLIENTS = {}

s3_client = None
if AWS_KEY and AWS_SECRET and AWS_BUCKET:
    try:
        s3_client = boto3.client('s3', aws_access_key_id=AWS_KEY, aws_secret_access_key=AWS_SECRET, region_name=AWS_REGION)
        print("☁️ AWS S3 Static Media Pipeline Verified & Active.")
    except Exception as e:
        print(f"⚠️ AWS S3 Initialization Warning: {e}")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def provision_lightning_wallet(username):
    """Two-step LNbits Core API handshake with local cryptographic fallback."""
    if not LNBITS_MASTER_KEY:
        return {"id": secrets.token_hex(16), "admin_key": "local_mock", "invoice_key": "local_mock"}
        
    headers = {"X-Api-Key": LNBITS_MASTER_KEY, "Content-type": "application/json"}
    
    try:
        res1 = requests.get(f"{LNBITS_URL}/api/v1/wallet", headers=headers)
        if res1.status_code == 200:
            master_user_id = res1.json().get('user')
            payload = {"user": master_user_id, "name": f"Vault_{username}"}
            res2 = requests.post(f"{LNBITS_URL}/api/v1/wallet", json=payload, headers=headers)
            
            if res2.status_code in [200, 201]:
                data = res2.json()
                print(f"✅ LNbits Wallet Successfully Provisioned for {username}")
                return {
                    "id": data.get('id'),
                    "admin_key": data.get('adminkey'),
                    "invoice_key": data.get('inkey')
                }
            else:
                print(f"❌ Sub-wallet rejected: {res2.text}")
        else:
            print(f"❌ LNbits Auth Fault: {res1.text}")
            
    except Exception as e:
        print(f"⚠️ API Fault: {e}")
        
    print(f"⚠️ Activating Failsafe: Generating local secure vault for {username}")
    return {"id": f"loc_{secrets.token_hex(12)}", "admin_key": "local_mock", "invoice_key": "local_mock"}

# --- AUTOMATED SELF-HEALING SCHEMATIC GENERATOR WITH MIGRATIONS ---
def init_db():
    if not NEON_URL:
        print("❌ CRITICAL: No connection string found! Check your .env file.")
        return
    print("🐘 Scanning and syncing structural tables with Cloud PostgreSQL cluster...")
    try:
        with psycopg2.connect(NEON_URL) as conn:
            with conn.cursor() as cursor:
                cursor.execute(f'''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        bio TEXT DEFAULT 'No bio written yet.',
                        profile_pic TEXT DEFAULT '{DEFAULT_AVATAR_CDN}',
                        stripe_account VARCHAR(255) DEFAULT ''
                    );
                ''')
                
                # E2EE MIGRATIONS: Public Key and Escrowed Encrypted Private Key
                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='public_key';")
                if not cursor.fetchone(): 
                    print("🔐 Upgrading database schema: Injecting Client-Side Public Key matrix...")
                    cursor.execute("ALTER TABLE users ADD COLUMN public_key TEXT DEFAULT '';")
                
                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='encrypted_private_key';")
                if not cursor.fetchone(): 
                    print("🔐 Upgrading database schema: Injecting Encrypted Private Key Escrow...")
                    cursor.execute("ALTER TABLE users ADD COLUMN encrypted_private_key TEXT DEFAULT '';")
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS invite_keys (
                        key VARCHAR(255) PRIMARY KEY,
                        generated_by VARCHAR(255) NOT NULL,
                        expires_at BIGINT NOT NULL,
                        status VARCHAR(50) DEFAULT 'unused'
                    );
                ''')
                
                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name='invite_keys' AND column_name='used_by';")
                if not cursor.fetchone(): cursor.execute("ALTER TABLE invite_keys ADD COLUMN used_by VARCHAR(255) DEFAULT NULL;")
                    
                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='first_login';")
                if not cursor.fetchone(): cursor.execute("ALTER TABLE users ADD COLUMN first_login BOOLEAN DEFAULT TRUE;")

                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='ln_wallet_id';")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE users ADD COLUMN ln_wallet_id VARCHAR(255) DEFAULT '';")
                    cursor.execute("ALTER TABLE users ADD COLUMN ln_admin_key VARCHAR(255) DEFAULT '';")
                    cursor.execute("ALTER TABLE users ADD COLUMN ln_invoice_key VARCHAR(255) DEFAULT '';")

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS feed_posts (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) NOT NULL,
                        content TEXT NOT NULL,
                        image_url TEXT DEFAULT '',
                        likes_count INT DEFAULT 0,
                        dislikes_count INT DEFAULT 0,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS wall_posts (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) NOT NULL,
                        profile_owner VARCHAR(255) NOT NULL,
                        content TEXT NOT NULL,
                        image_url TEXT DEFAULT '',
                        likes_count INT DEFAULT 0,
                        dislikes_count INT DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS feed_comments (
                        id SERIAL PRIMARY KEY,
                        post_id INT REFERENCES feed_posts(id) ON DELETE CASCADE,
                        username VARCHAR(255) NOT NULL,
                        content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS wall_comments (
                        id SERIAL PRIMARY KEY,
                        post_id INT REFERENCES wall_posts(id) ON DELETE CASCADE,
                        username VARCHAR(255) NOT NULL,
                        content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS escrow_transactions (
                        id SERIAL PRIMARY KEY,
                        sender VARCHAR(255) NOT NULL,
                        receiver VARCHAR(255) NOT NULL,
                        amount_cents INTEGER NOT NULL,
                        status VARCHAR(50) DEFAULT 'held_in_escrow',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                
                # E2EE ciphertext will be stored here in raw JSON format sent from the browser
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS encrypted_messages (
                        id SERIAL PRIMARY KEY,
                        sender VARCHAR(255) NOT NULL,
                        receiver VARCHAR(255) NOT NULL,
                        ciphertext TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS group_chats (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        creator VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS group_chat_members (
                        id SERIAL PRIMARY KEY,
                        group_id INT REFERENCES group_chats(id) ON DELETE CASCADE,
                        username VARCHAR(255) NOT NULL,
                        UNIQUE(group_id, username)
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS group_messages (
                        id SERIAL PRIMARY KEY,
                        group_id INT REFERENCES group_chats(id) ON DELETE CASCADE,
                        sender VARCHAR(255) NOT NULL,
                        message TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS group_pools (
                        id SERIAL PRIMARY KEY,
                        group_id INT REFERENCES group_chats(id) ON DELETE CASCADE,
                        name VARCHAR(255) NOT NULL,
                        status VARCHAR(50) DEFAULT 'active',
                        released_to VARCHAR(255) DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS pool_contributions (
                        id SERIAL PRIMARY KEY,
                        pool_id INT REFERENCES group_pools(id) ON DELETE CASCADE,
                        username VARCHAR(255) NOT NULL,
                        amount_cents INTEGER NOT NULL,
                        status VARCHAR(50) DEFAULT 'held_in_escrow',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                ''')

                cursor.execute("""
                    INSERT INTO invite_keys (key, generated_by, expires_at, status)
                    VALUES ('GENESIS-123', 'SYSTEM', 2147483647, 'unused')
                    ON CONFLICT (key) DO NOTHING;
                """)
            conn.commit()
        print("✅ Neon Database completely built, verified, and operational.")
    except Exception as e:
        print(f"❌ DATABASE AUTO-INITIALIZATION FAILURE: {e}")

def run_escrow_expiration_janitor():
    while True:
        try:
            if NEON_URL:
                with psycopg2.connect(NEON_URL) as conn:
                    with conn.cursor() as cursor:
                        cursor.execute("UPDATE escrow_transactions SET status = 'refunded_to_sender' WHERE status = 'held_in_escrow' AND created_at < NOW() - INTERVAL '24 hours';")
                        cursor.execute("UPDATE pool_contributions SET status = 'refunded' WHERE status = 'held_in_escrow' AND created_at < NOW() - INTERVAL '24 hours';")
                        cursor.execute("UPDATE group_pools SET status = 'refunded' WHERE status = 'active' AND created_at < NOW() - INTERVAL '24 hours';")
                    conn.commit()
        except Exception as e:
            print(f"⚠️ Janitor Loop Processing Intercept: {e}")
        time.sleep(30)

@app.route('/')
def index(): return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session: return redirect(url_for('login'))
    show_welcome = session.pop('is_first_login', False)
    return render_template('dashboard.html', username=session['username'], show_welcome=show_welcome)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        invite_key = request.form.get('invite_key', '').strip()
        username = request.form['username'].strip()
        password = request.form['password']
        try:
            with psycopg2.connect(NEON_URL) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT expires_at, status FROM invite_keys WHERE key = %s;", (invite_key,))
                    key_row = cursor.fetchone()
                    if not key_row or key_row[1] != 'unused' or int(time.time()) > key_row[0]:
                        flash("Key missing, consumed, or expired.", "error")
                        return render_template('login.html', title="Register")
                    
                    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    
                    wallet_data = provision_lightning_wallet(username)
                    ln_id = wallet_data['id'] if wallet_data else ''
                    ln_admin = wallet_data['admin_key'] if wallet_data else ''
                    ln_inv = wallet_data['invoice_key'] if wallet_data else ''
                    
                    try:
                        cursor.execute("""
                            INSERT INTO users (username, password_hash, ln_wallet_id, ln_admin_key, ln_invoice_key) 
                            VALUES (%s, %s, %s, %s, %s);
                        """, (username, hashed, ln_id, ln_admin, ln_inv))
                        cursor.execute("UPDATE invite_keys SET status = 'used', used_by = %s WHERE key = %s;", (username, invite_key))
                        conn.commit()
                        flash("Handshake locked. Profile & Vault initialized! Please log in.", "success")
                        return redirect(url_for('login'))
                    except psycopg2.IntegrityError: 
                        flash("Username already claimed.", "error")
        except Exception as e: 
            flash(f"Internal Handshake Failure: {e}", "error")
    return render_template('login.html', title="Register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        try:
            with psycopg2.connect(NEON_URL) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT password_hash, first_login FROM users WHERE username = %s;", (username,))
                    row = cursor.fetchone()
            
            if row and bcrypt.checkpw(password.encode('utf-8'), row[0].encode('utf-8')):
                session['username'] = username
                if row[1]: 
                    session['is_first_login'] = True
                    with psycopg2.connect(NEON_URL) as conn:
                        with conn.cursor() as cursor:
                            cursor.execute("UPDATE users SET first_login = FALSE WHERE username = %s;", (username,))
                        conn.commit()
                return redirect(url_for('dashboard'))
            flash("Invalid credentials.", "error")
        except Exception as e: 
            flash(f"Internal Connection Drop: {e}", "error")
    return render_template('login.html', title="Login")

@app.route('/logout')
def logout(): 
    session.pop('username', None)
    return redirect(url_for('login'))
# --- END-TO-END ENCRYPTION (E2EE) PUBLIC KEY REGISTRY & ESCROW ---
@app.route('/api/crypto/keys', methods=['POST'])
def sync_crypto_keys():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    pub_key = request.json.get('public_key')
    enc_priv_key = request.json.get('encrypted_private_key', '')
    if not pub_key: return jsonify({"error": "Payload missing cryptographic key"}), 400
    
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET public_key = %s, encrypted_private_key = %s WHERE username = %s;", 
                           (pub_key, enc_priv_key, session['username']))
        conn.commit()
    return jsonify({"status": "SUCCESS", "message": "Cryptographic enclave synced to network."})

@app.route('/api/crypto/my_keys', methods=['GET'])
def get_my_escrowed_keys():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT public_key, encrypted_private_key FROM users WHERE username = %s;", (session['username'],))
            row = cursor.fetchone()
            
    if row and row.get('public_key'): 
        return jsonify({"public_key": row['public_key'], "encrypted_private_key": row.get('encrypted_private_key', '')})
    return jsonify({"error": "No keys found"}), 404

@app.route('/api/crypto/public_key/<target_user>', methods=['GET'])
def get_public_key(target_user):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT public_key FROM users WHERE username = %s;", (target_user,))
            row = cursor.fetchone()
            
    if row and row.get('public_key'): return jsonify({"public_key": row['public_key']})
    return jsonify({"error": "Key not found in directory"}), 404

# --- STANDARD PLATFORM ROUTING ---
@app.route('/api/upload', methods=['POST'])
def handle_upload():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if 'photo' not in request.files: return jsonify({"error": "No file chunk found"}), 400
    file = request.files['photo']
    if file.filename == '': return jsonify({"error": "No file name selected"}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
        if s3_client and AWS_BUCKET:
            try:
                s3_client.upload_fileobj(file, AWS_BUCKET, filename, ExtraArgs={"ACL": "public-read", "ContentType": file.content_type})
                return jsonify({"url": f"https://{AWS_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{filename}"})
            except Exception: pass
                
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({"url": f"/static/uploads/{filename}"})
        
    return jsonify({"error": "Extension rejected"}), 400

@app.route('/api/users', methods=['GET'])
def get_network_users():
    if 'username' not in session: return jsonify([]), 401
    try:
        with psycopg2.connect(NEON_URL) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT username, profile_pic FROM users;")
                return jsonify(cursor.fetchall())
    except Exception: return jsonify([]), 500

@app.route('/api/profile/<username>', methods=['GET', 'POST'])
def handle_profile(username):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if request.method == 'POST' and username == session['username']:
        bio = request.json.get('bio')
        profile_pic = request.json.get('profile_pic')
        with psycopg2.connect(NEON_URL) as conn:
            with conn.cursor() as cursor:
                if bio is not None: cursor.execute("UPDATE users SET bio = %s WHERE username = %s;", (bio.strip(), username))
                if profile_pic is not None: cursor.execute("UPDATE users SET profile_pic = %s WHERE username = %s;", (profile_pic, username))
            conn.commit()
        return jsonify({"status": "updated"})
        
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT username, bio, profile_pic, ln_wallet_id FROM users WHERE username = %s;", (username,))
            row = cursor.fetchone()
    if row: return jsonify(row)
    return jsonify({"error": "Profile missing"}), 404

@app.route('/api/profile/<username>/posts', methods=['GET', 'POST'])
def handle_profile_posts(username):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if request.method == 'POST':
        content = request.json.get('content', '').strip()
        image_url = request.json.get('image_url', '').strip()
        if content or image_url:
            with psycopg2.connect(NEON_URL) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("INSERT INTO wall_posts (username, profile_owner, content, image_url) VALUES (%s, %s, %s, %s);", (session['username'], username, content, image_url))
                conn.commit()
        return jsonify({"status": "success"})
        
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT id, username, content, image_url, likes_count, dislikes_count, created_at FROM wall_posts WHERE profile_owner = %s ORDER BY id DESC;", (username,))
            posts = cursor.fetchall()
            wall_payload = []
            for p in posts:
                post_id = p['id']
                cursor.execute("SELECT username, content FROM wall_comments WHERE post_id = %s ORDER BY created_at ASC", (post_id,))
                p['comments'] = [{"username": c['username'], "content": c['content']} for c in cursor.fetchall()]
                wall_payload.append(p)
            return jsonify(wall_payload)

@app.route('/invite/generate', methods=['POST'])
def generate_key():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    new_key = f"METRO-{secrets.token_hex(4).upper()}"
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO invite_keys (key, generated_by, expires_at) VALUES (%s, %s, %s);", (new_key, session['username'], int(time.time()) + 600))
        conn.commit()
    return jsonify({"key": new_key})

@app.route('/api/invites/ledger', methods=['GET'])
def get_invite_ledger():
    if 'username' not in session: return jsonify([]), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT key, status, used_by, expires_at FROM invite_keys WHERE generated_by = %s ORDER BY expires_at DESC;", (session['username'],))
            return jsonify(cursor.fetchall())

@app.route('/api/feed', methods=['GET', 'POST'])
def handle_feed():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if request.method == 'POST':
        content = request.json.get('content', '').strip()
        image_url = request.json.get('image_url', '').strip()
        if content or image_url:
            with psycopg2.connect(NEON_URL) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("INSERT INTO feed_posts (username, content, image_url) VALUES (%s, %s, %s);", (session['username'], content, image_url))
                conn.commit()
        return jsonify({"status": "success"})
        
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT f.id, f.username, f.content, f.image_url, f.likes_count, f.dislikes_count, f.timestamp, u.profile_pic FROM feed_posts f JOIN users u ON f.username = u.username ORDER BY f.id DESC;")
            posts = cursor.fetchall()
            feed_payload = []
            for p in posts:
                post_id = p['id']
                cursor.execute("SELECT username, content FROM feed_comments WHERE post_id = %s ORDER BY created_at ASC", (post_id,))
                p['comments'] = [{"username": c['username'], "content": c['content']} for c in cursor.fetchall()]
                feed_payload.append(p)
            return jsonify(feed_payload)

@app.route('/api/feed/<int:post_id>/like', methods=['POST'])
def like_feed_post(post_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor: cursor.execute("UPDATE feed_posts SET likes_count = likes_count + 1 WHERE id = %s", (post_id,))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/feed/<int:post_id>/dislike', methods=['POST'])
def dislike_feed_post(post_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor: cursor.execute("UPDATE feed_posts SET dislikes_count = dislikes_count + 1 WHERE id = %s", (post_id,))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/feed/<int:post_id>/comment', methods=['POST'])
def comment_feed_post(post_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    content = (request.get_json() or {}).get('content', '').strip()
    if not content: return jsonify({"error": "Empty comment"}), 400
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor: cursor.execute("INSERT INTO feed_comments (post_id, username, content) VALUES (%s, %s, %s)", (post_id, session['username'], content))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/feed/<int:post_id>/share', methods=['POST'])
def share_feed_post(post_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    caption = (request.get_json() or {}).get('caption', '').strip()
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username, content, image_url FROM feed_posts WHERE id = %s", (post_id,))
            post = cursor.fetchone()
            if not post: return jsonify({"error": "Not found"}), 404
            shared_text = f"{caption}\n\n🔄 Shared @feed broadcast from @{post[0]}:\n\"{post[1]}\"" if caption else f"🔄 Shared @feed broadcast from @{post[0]}:\n\"{post[1]}\""
            cursor.execute("INSERT INTO wall_posts (username, profile_owner, content, image_url) VALUES (%s, %s, %s, %s)", (session['username'], session['username'], shared_text, post[2]))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/profile/posts/<int:post_id>/like', methods=['POST'])
def like_wall_post(post_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor: cursor.execute("UPDATE wall_posts SET likes_count = likes_count + 1 WHERE id = %s", (post_id,))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/profile/posts/<int:post_id>/dislike', methods=['POST'])
def dislike_wall_post(post_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor: cursor.execute("UPDATE wall_posts SET dislikes_count = dislikes_count + 1 WHERE id = %s", (post_id,))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/profile/posts/<int:post_id>/comment', methods=['POST'])
def comment_wall_post(post_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    content = (request.get_json() or {}).get('content', '').strip()
    if not content: return jsonify({"error": "Empty comment"}), 400
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor: cursor.execute("INSERT INTO wall_comments (post_id, username, content) VALUES (%s, %s, %s)", (post_id, session['username'], content))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/profile/posts/<int:post_id>/share', methods=['POST'])
def share_wall_post(post_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    caption = (request.get_json() or {}).get('caption', '').strip()
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username, content, image_url FROM wall_posts WHERE id = %s", (post_id,))
            post = cursor.fetchone()
            if not post: return jsonify({"error": "Not found"}), 404
            shared_text = f"{caption}\n\n🔄 Shared wall update from @{post[0]}:\n\"{post[1]}\"" if caption else f"🔄 Shared wall update from @{post[0]}:\n\"{post[1]}\""
            cursor.execute("INSERT INTO wall_posts (username, profile_owner, content, image_url) VALUES (%s, %s, %s, %s)", (session['username'], session['username'], shared_text, post[2]))
        conn.commit()
    return jsonify({"status": "SUCCESS"})
@app.route('/api/groups/create', methods=['POST'])
def create_group_chat_node():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    name = request.json.get('name', '').strip() or "Unnamed Workspace Cluster"
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO group_chats (name, creator) VALUES (%s, %s) RETURNING id;", (name, session['username']))
            group_id = cursor.fetchone()[0]
            cursor.execute("INSERT INTO group_chat_members (group_id, username) VALUES (%s, %s);", (group_id, session['username']))
        conn.commit()
    return jsonify({"status": "SUCCESS", "group_id": group_id})

@app.route('/api/groups/list', methods=['GET'])
def list_user_group_nodes():
    if 'username' not in session: return jsonify([]), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT g.id, g.name, g.creator FROM group_chats g JOIN group_chat_members m ON g.id = m.group_id WHERE m.username = %s ORDER BY g.id DESC;", (session['username'],))
            return jsonify(cursor.fetchall())

@app.route('/api/groups/<int:group_id>/add_member', methods=['POST'])
def add_member_to_group(group_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    target_user = request.json.get('username', '').strip()
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor: cursor.execute("INSERT INTO group_chat_members (group_id, username) VALUES (%s, %s) ON CONFLICT DO NOTHING;", (group_id, target_user))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/groups/<int:group_id>/members', methods=['GET'])
def get_group_members_list(group_id):
    if 'username' not in session: return jsonify([]), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username FROM group_chat_members WHERE group_id = %s ORDER BY username ASC;", (group_id,))
            return jsonify([row[0] for row in cursor.fetchall()])

@app.route('/api/groups/<int:group_id>/messages', methods=['GET'])
def get_group_chat_history_logs(group_id):
    if 'username' not in session: return jsonify([]), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT sender, message as text, timestamp FROM group_messages WHERE group_id = %s ORDER BY id ASC;", (group_id,))
            return jsonify(cursor.fetchall())

# --- REAL-TIME ASYNC MULTI-USER POOLED FINANCIAL CIRCUITS ---
@app.route('/api/groups/<int:group_id>/pools/create', methods=['POST'])
def provision_group_money_pool(group_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    name = request.json.get('name', '').strip() or "General Asset Funding Pool"
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO group_pools (group_id, name) VALUES (%s, %s) RETURNING id;", (group_id, name))
            pool_id = cursor.fetchone()[0]
        conn.commit()
    return jsonify({"status": "SUCCESS", "pool_id": pool_id})

@app.route('/api/groups/<int:group_id>/pools', methods=['GET'])
def list_group_money_pools(group_id):
    if 'username' not in session: return jsonify([]), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT id, name, status, released_to FROM group_pools WHERE group_id = %s ORDER BY id DESC;", (group_id,))
            pools = cursor.fetchall()
            for p in pools:
                cursor.execute("SELECT COALESCE(SUM(amount_cents), 0) FROM pool_contributions WHERE pool_id = %s AND status='held_in_escrow';", (p['id'],))
                p['total_escrow_cents'] = cursor.fetchone()[0]
            return jsonify(pools)

@app.route('/api/pools/<int:pool_id>/contribute', methods=['POST'])
def commit_capital_to_pool(pool_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    try: amount_cents = int(float(request.json.get('amount')) * 100)
    except Exception: return jsonify({"error": "Malformed currency payload architecture"}), 400
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor: cursor.execute("INSERT INTO pool_contributions (pool_id, username, amount_cents) VALUES (%s, %s, %s);", (pool_id, session['username'], amount_cents))
        conn.commit()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/pools/<int:pool_id>/release', methods=['POST'])
def clear_and_disburse_pool_balances(pool_id):
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    target_recipient = request.json.get('receiver', '').strip()
    if not target_recipient: return jsonify({"error": "No designated recipient matching operational matrices"}), 400
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT g.creator FROM group_chats g JOIN group_pools p ON g.id = p.group_id WHERE p.id = %s;", (pool_id,))
            res = cursor.fetchone()
            if not res or res[0] != session['username']: return jsonify({"error": "Access Forbidden: Only workspace creator can disburse pooled balances"}), 403
            cursor.execute("UPDATE group_pools SET status = 'released_to_user', released_to = %s WHERE id = %s AND status = 'active';", (target_recipient, pool_id))
            cursor.execute("UPDATE pool_contributions SET status = 'released' WHERE pool_id = %s AND status = 'held_in_escrow';", (pool_id,))
        conn.commit()
    return jsonify({"status": "SUCCESS", "message": f"Balances released directly to @{target_recipient}"})

# --- FINANCIAL ESCROW CIRCUITS ---
@app.route('/api/escrow/create', methods=['POST'])
def create_escrow():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    receiver = request.json.get('receiver')
    amount = request.json.get('amount')
    try: amount_cents = int(float(amount) * 100)
    except ValueError: return jsonify({"error": "Invalid format"}), 400
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO escrow_transactions (sender, receiver, amount_cents, status) VALUES (%s, %s, %s, 'awaiting_payment') RETURNING id;", (session['username'], receiver, amount_cents))
            tx_id = cursor.fetchone()[0]
        conn.commit()
    return jsonify({"message": "Escrow mounted.", "id": tx_id})

@app.route('/api/escrow/list', methods=['GET'])
def list_escrow():
    if 'username' not in session: return jsonify([]), 401
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT id, sender, receiver, amount_cents, status FROM escrow_transactions WHERE sender = %s OR receiver = %s;", (session['username'], session['username']))
            return jsonify(cursor.fetchall())

@app.route('/api/escrow/release', methods=['POST'])
def release_escrow():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    tx_id = request.json.get('id')
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT sender, receiver, amount_cents, status FROM escrow_transactions WHERE id = %s;", (tx_id,))
            row = cursor.fetchone()
            if not row or row[0] != session['username'] or row[3] != 'held_in_escrow': return jsonify({"error": "Forbidden transaction release matrix action"}), 403
            cursor.execute("UPDATE escrow_transactions SET status = 'released_to_receiver' WHERE id = %s;", (tx_id,))
        conn.commit()
    return jsonify({"message": f"Contract cleared. Balances released to @{row[1]}."})

# --- FINANCIAL ENGINE: LNbits CORE INTEGRATION ---
@app.route('/api/wallet/balance', methods=['GET'])
def get_wallet_balance():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    
    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT ln_invoice_key FROM users WHERE username = %s;", (session['username'],))
            row = cursor.fetchone()
            
    if not row or not row.get('ln_invoice_key') or row['ln_invoice_key'] == 'local_mock':
        return jsonify({"balance_sats": 0, "status": "mock_vault_active"})
        
    try:
        headers = {"X-Api-Key": row['ln_invoice_key']}
        res = requests.get(f"{LNBITS_URL}/api/v1/wallet", headers=headers)
        if res.status_code == 200:
            balance_msat = res.json().get('balance', 0)
            return jsonify({"balance_sats": balance_msat // 1000, "status": "live"})
        return jsonify({"error": "LNbits node rejected request"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/wallet/invoice', methods=['POST'])
def generate_lightning_invoice():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    amount_sats = request.json.get('amount_sats', 0)
    memo = request.json.get('memo', f"Hub Escrow Deposit: {session['username']}")
    
    try: amount_sats = int(amount_sats)
    except ValueError: return jsonify({"error": "Malformed currency value"}), 400

    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT ln_invoice_key FROM users WHERE username = %s;", (session['username'],))
            row = cursor.fetchone()

    if not row or row['ln_invoice_key'] == 'local_mock':
        return jsonify({"error": "Vault is in local failsafe mode. Connect a live LNbits node."}), 400

    try:
        headers = {"X-Api-Key": row['ln_invoice_key'], "Content-type": "application/json"}
        payload = {"out": False, "amount": amount_sats, "memo": memo}
        res = requests.post(f"{LNBITS_URL}/api/v1/payments", json=payload, headers=headers)
        
        if res.status_code in [200, 201]:
            data = res.json()
            return jsonify({"payment_request": data.get('payment_request'), "payment_hash": data.get('payment_hash')})
        return jsonify({"error": f"LNbits Error: {res.text}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/wallet/pay', methods=['POST'])
def pay_lightning_invoice():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    bolt11 = request.json.get('bolt11', '').strip()
    if not bolt11: return jsonify({"error": "Missing invoice payload"}), 400

    with psycopg2.connect(NEON_URL) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT ln_admin_key FROM users WHERE username = %s;", (session['username'],))
            row = cursor.fetchone()

    if not row or row['ln_admin_key'] == 'local_mock':
        return jsonify({"error": "Vault is in local failsafe mode. Cannot route external capital."}), 400

    try:
        headers = {"X-Api-Key": row['ln_admin_key'], "Content-type": "application/json"}
        payload = {"out": True, "bolt11": bolt11}
        res = requests.post(f"{LNBITS_URL}/api/v1/payments", json=payload, headers=headers)
        
        if res.status_code in [200, 201]:
            return jsonify({"status": "SUCCESS", "message": "Capital routed successfully."})
        return jsonify({"error": f"LNbits Error: {res.text}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- STRIPE CRYPTO ONRAMP GATEWAY & WEBHOOK ---
@app.route('/api/stripe/onramp', methods=['POST'])
def create_onramp_session():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    try:
        onramp_session = stripe.crypto.OnrampSession.create(
            destination_details={
                "network": "bitcoin",
                "wallet_addresses": {"bitcoin": "tb1q_placeholder_vault_address_for_testing"}
            },
            customer_ip_address=request.remote_addr,
            metadata={"username": session['username']}
        )
        return jsonify({"client_secret": onramp_session.client_secret})
    except Exception as e:
        print(f"❌ Stripe Crypto Auth Error: {e}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    request_data = request.data
    sig_header = request.headers.get('Stripe-Signature', '')

    try:
        event = stripe.Webhook.construct_event(payload=request_data, sig_header=sig_header, secret=webhook_secret)
    except ValueError as e:
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify({"error": "Invalid cryptographic signature"}), 400

    if event['type'] == 'crypto.onramp_session.updated':
        session_obj = event['data']['object']
        if session_obj['status'] == 'fulfillment_complete':
            username = session_obj.get('metadata', {}).get('username')
            amount = session_obj.get('destination_details', {}).get('amount')
            print(f"💰 STRIPE SETTLEMENT: Crypto delivered to {username}. Amount: {amount}")

    return jsonify({"status": "success"}), 200

# --- LIVE ASYNC WEBSOCKET WORKSPACE MULTIPLEXER (BLIND COURIER ROUTING) ---
def fetch_message_history(username):
    history = []
    try:
        with psycopg2.connect(NEON_URL) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT sender, receiver, ciphertext FROM encrypted_messages WHERE sender = %s OR receiver = %s ORDER BY id ASC;", (username, username))
                for row in cursor.fetchall():
                    history.append({"sender": row['sender'], "receiver": row['receiver'], "text": row['ciphertext']})
    except Exception as e: print(f"❌ History Recovery Failure: {e}")
    return history

async def ws_handler(websocket):
    try:
        raw_identity = await websocket.recv()
        identity_data = json.loads(raw_identity)
        username = identity_data.get("username")
    except Exception: return
    if not username: return
    
    CONNECTED_CLIENTS[username] = websocket
    print(f"📡 Node connected: @{username}")
    
    try:
        presence_payload = json.dumps({"is_presence": True, "online_users": list(CONNECTED_CLIENTS.keys())})
        for client in list(CONNECTED_CLIENTS.values()):
            try: await client.send(presence_payload)
            except Exception: pass
            
        user_history = fetch_message_history(username)
        await websocket.send(json.dumps({"is_history": True, "history": user_history}))
        
        async for message in websocket:
            try:
                data = json.loads(message)
                
                # Group Chats: Currently plaintext
                if data.get("group_id"):
                    group_id, text = data.get("group_id"), data.get("text")
                    with psycopg2.connect(NEON_URL) as conn:
                        with conn.cursor() as cursor:
                            cursor.execute("INSERT INTO group_messages (group_id, sender, message) VALUES (%s, %s, %s);", (group_id, username, text))
                            cursor.execute("SELECT username FROM group_chat_members WHERE group_id = %s;", (group_id,))
                            members = [m[0] for m in cursor.fetchall()]
                        conn.commit()
                    output_payload = json.dumps({"group_id": group_id, "sender": username, "text": text})
                    for m in members:
                        if m in CONNECTED_CLIENTS: await CONNECTED_CLIENTS[m].send(output_payload)
                    continue
                
                if data.get("type") == "typing":
                    target = data.get("receiver")
                    if target in CONNECTED_CLIENTS:
                        await CONNECTED_CLIENTS[target].send(json.dumps({"is_typing": True, "sender": username}))
                    continue
                
                sender, receiver, text = data.get("sender"), data.get("receiver"), data.get("text")
                if sender and receiver and text:
                    # BLIND FORWARDING: 'text' is already encrypted by the client's WebCrypto API.
                    with psycopg2.connect(NEON_URL) as conn:
                        with conn.cursor() as cursor:
                            cursor.execute("INSERT INTO encrypted_messages (sender, receiver, ciphertext) VALUES (%s, %s, %s);", (sender, receiver, text))
                        conn.commit()
                    output_payload = json.dumps({"sender": sender, "receiver": receiver, "text": text})
                    if receiver in CONNECTED_CLIENTS: await CONNECTED_CLIENTS[receiver].send(output_payload)
                    if sender in CONNECTED_CLIENTS: await CONNECTED_CLIENTS[sender].send(output_payload)
            except Exception as e: print(f"❌ Message Routing Exception: {e}")
    except websockets.exceptions.ConnectionClosed: pass
    finally:
        CONNECTED_CLIENTS.pop(username, None)
        disconnect_payload = json.dumps({"is_presence_update": True, "online_users": list(CONNECTED_CLIENTS.keys())})
        for client in list(CONNECTED_CLIENTS.values()):
            try: await client.send(disconnect_payload)
            except Exception: pass

def run_flask():
    try: app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    except Exception as e: print(f"❌ PORT BIND FAULT: {e}")

async def run_ws(port):
    print(f"🚀 Secure Mesh Binding to Port {port}")
    async with websockets.serve(ws_handler, "0.0.0.0", port): 
        await asyncio.Event().wait()

if __name__ == '__main__':
    mode = os.getenv("RUN_MODE", "LOCAL")
    
    # Auto-migrate database structure
    init_db()
    
    # Mount the financial escrow expiration janitor
    threading.Thread(target=run_escrow_expiration_janitor, daemon=True).start()

    if mode == "WEBSOCKET":
        # CLOUD PRODUCTION: Runs only the real-time multiplexer on Render's dynamic port
        port = int(os.getenv("PORT", 5001))
        asyncio.run(run_ws(port))
    else:
        # LOCAL TESTING: Runs both Flask and WebSockets on dedicated local ports
        print("Launching Phase 2 E2EE Framework Core (Local Sandbox)...")
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()
        asyncio.run(run_ws(5001))
