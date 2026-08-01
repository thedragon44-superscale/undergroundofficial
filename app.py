import os
import json
import asyncio
import threading
import datetime
import websockets
import bcrypt
import psycopg2
import stripe
import requests
import uuid
import boto3
from botocore.client import Config
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pywebpush import webpush, WebPushException
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime, timedelta
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
# Tell Flask it is behind a secure Nginx proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Ensure cookies work across both streetcode101.com and www.streetcode101.com
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# ----------------------
# KILL SWITCH: Randomizing the secret key auto-wipes all active user sessions when the server reboots.
app.secret_key = os.urandom(24)
CORS(app)

@app.route('/health', methods=['GET', 'HEAD'])
def health_check():
    return "OK", 200

# Stripe Fiat Bridge
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

connected_clients = {}

# --- SOVEREIGN DATABASE & STORAGE CONFIGURATIONS ---

def get_db_connection():
    db_url = os.getenv("NEON_DATABASE_URL")
    if db_url:
        return psycopg2.connect(db_url)
    return psycopg2.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        database=os.getenv('DB_NAME', 'streetcode'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASS', 'password')
    )

# MinIO / Sovereign Object Storage Client
s3_client = boto3.client(
    's3',
    endpoint_url=os.getenv('AWS_ENDPOINT_URL'),
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    config=Config(signature_version='s3v4'),
    region_name=os.getenv('AWS_REGION', 'us-east-1')
)
BUCKET_NAME = os.getenv('AWS_STORAGE_BUCKET_NAME', 'streetcode-assets')

# --- AUTOMATED EMAIL ENGINE ---
def send_system_email(to_address, subject, body_html):
    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    
    if not smtp_host or not smtp_user:
        print("[-] SMTP credentials missing. Email aborted.")
        return False
        
    msg = MIMEMultipart()
    msg['From'] = "Street Code 101 <noreply@streetcode101.com>"
    msg['To'] = to_address
    msg['Subject'] = subject
    msg.attach(MIMEText(body_html, 'html'))
    
    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[-] Email Dispatch Failed: {e}")
        return False

# --- WEB PUSH NOTIFICATION ENGINE ---
def send_web_push(username, title, body):
    vapid_private_key = os.getenv('VAPID_PRIVATE_KEY')
    vapid_claim_email = os.getenv('VAPID_CLAIM_EMAIL', 'mailto:admin@streetcode101.com')
    
    if not vapid_private_key:
        return False
        
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, subscription_info FROM push_subscriptions WHERE username = %s", (username,))
    subs = cur.fetchall()
    
    payload = json.dumps({
        "title": title,
        "body": body,
        "icon": "/static/streetbook_logo.png",
        "url": "/dashboard"
    })
    
    for sub in subs:
        sub_id = sub[0]
        try:
            sub_data = json.loads(sub[1])
            webpush(
                subscription_info=sub_data,
                data=payload,
                vapid_private_key=vapid_private_key,
                vapid_claims={"sub": vapid_claim_email}
            )
        except WebPushException as ex:
            if ex.response and ex.response.status_code in [404, 410]:
                cur.execute("DELETE FROM push_subscriptions WHERE id = %s", (sub_id,))
                
    conn.commit()
    conn.close()
    return True

# --- DATABASE INITIALIZATION & TIER MIGRATION ---
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 1. Users Table (Core Schema)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            public_key TEXT,
            encrypted_private_key TEXT,
            bio TEXT,
            profile_pic TEXT,
            ln_wallet_id TEXT,
            ln_admin_key TEXT,
            stripe_account TEXT,
            invited_by VARCHAR(50),
            is_pro BOOLEAN DEFAULT FALSE
        )
    ''')
    
    # Run Safe Migrations for New Columns (Aliases, Email, Admin, Street Cred)
    new_columns = [
        ("email", "VARCHAR(150) UNIQUE"),
        ("is_email_verified", "BOOLEAN DEFAULT FALSE"),
        ("email_verify_token", "VARCHAR(100)"),
        ("pwd_reset_token", "VARCHAR(100)"),
        ("pwd_reset_expires", "BIGINT"),
        ("display_name", "VARCHAR(50)"),
        ("reputation_score", "INTEGER DEFAULT 0"),
        ("is_admin", "BOOLEAN DEFAULT FALSE")
    ]
    
    for col_name, col_type in new_columns:
        try:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
            conn.commit()
        except Exception:
            conn.rollback()

    # 2. Street Cred Ledger
    cur.execute('''
        CREATE TABLE IF NOT EXISTS street_cred_votes (
            id SERIAL PRIMARY KEY,
            voter VARCHAR(50) NOT NULL,
            target_username VARCHAR(50) NOT NULL,
            vote_value INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(voter, target_username)
        )
    ''')

    # 3. Invite Keys Table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS invite_keys (
            id SERIAL PRIMARY KEY,
            key VARCHAR(50) UNIQUE NOT NULL,
            creator VARCHAR(50) NOT NULL,
            generated_by VARCHAR(50),
            status VARCHAR(20) DEFAULT 'active',
            used_by VARCHAR(50),
            expires_at BIGINT
        )
    ''')

    # 4. Direct Messages Table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender VARCHAR(50) NOT NULL,
            receiver VARCHAR(50) NOT NULL,
            text TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    try:
        cur.execute("ALTER TABLE messages ADD COLUMN is_read BOOLEAN DEFAULT FALSE")
        conn.commit()
    except Exception:
        conn.rollback()

    # 5. Social Posts Table (Feed & Wall)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            content TEXT,
            image_url TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_wall_post BOOLEAN DEFAULT FALSE,
            target_username VARCHAR(50)
        )
    ''')

    # 6. Post Interactions
    cur.execute('''
        CREATE TABLE IF NOT EXISTS post_likes (
            id SERIAL PRIMARY KEY,
            post_id INTEGER NOT NULL,
            username VARCHAR(50) NOT NULL,
            is_dislike BOOLEAN DEFAULT FALSE
        )
    ''')
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS post_comments (
            id SERIAL PRIMARY KEY,
            post_id INTEGER NOT NULL,
            username VARCHAR(50) NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 7. Group Workspaces
    cur.execute('''
        CREATE TABLE IF NOT EXISTS group_chats (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            creator VARCHAR(50) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            username VARCHAR(50) NOT NULL,
            PRIMARY KEY (group_id, username)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS group_messages (
            id SERIAL PRIMARY KEY,
            group_id INTEGER NOT NULL,
            sender VARCHAR(50) NOT NULL,
            text TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 8. Financial Escrow & Pools
    cur.execute('''
        CREATE TABLE IF NOT EXISTS money_pools (
            id SERIAL PRIMARY KEY,
            group_id INTEGER NOT NULL,
            name VARCHAR(100) NOT NULL,
            creator VARCHAR(50) NOT NULL,
            total_escrow_cents INTEGER DEFAULT 0,
            status VARCHAR(20) DEFAULT 'active',
            released_to VARCHAR(50)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS pool_contributions (
            id SERIAL PRIMARY KEY,
            pool_id INTEGER NOT NULL,
            username VARCHAR(50) NOT NULL,
            amount_cents INTEGER NOT NULL
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS escrow_transactions (
            id SERIAL PRIMARY KEY,
            sender VARCHAR(50) NOT NULL,
            receiver VARCHAR(50) NOT NULL,
            amount_cents INTEGER NOT NULL,
            status VARCHAR(30) DEFAULT 'held_in_escrow',
            stripe_payment_intent_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS platform_treasury (
            id SERIAL PRIMARY KEY,
            source_escrow_id INTEGER REFERENCES escrow_transactions(id) ON DELETE SET NULL,
            amount_collected INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 9. Web Push Device Subscriptions
    cur.execute('''
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            subscription_info TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 10. Webhooks idempotency
    cur.execute("""
        CREATE TABLE IF NOT EXISTS processed_webhooks (
            event_id VARCHAR(255) PRIMARY KEY,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

def init_master_admin():
    admin_user = os.getenv('ADMIN_USERNAME', 'catch_flight')
    admin_pass = os.getenv('ADMIN_PASSWORD')
    if not admin_user or not admin_pass:
        return

    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT id FROM users WHERE username = %s", (admin_user,))
    existing_user = cur.fetchone()
    
    if not existing_user:
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(admin_pass.encode('utf-8'), salt).decode('utf-8')
        
        cur.execute("""
            INSERT INTO users (username, password_hash, is_pro, is_admin, email, is_email_verified) 
            VALUES (%s, %s, TRUE, TRUE, 'admin@streetcode101.com', TRUE)
        """, (admin_user, hashed_pw))
        conn.commit()
        print(f"[*] Master Admin '{admin_user}' Auto-Provisioned with Square Business Immunity.")
    else:
        # Guarantee existing admin account is upgraded with fail-safes
        cur.execute("""
            UPDATE users 
            SET is_admin = TRUE, is_pro = TRUE, email = 'admin@streetcode101.com', is_email_verified = TRUE 
            WHERE username = %s
        """, (admin_user,))
        conn.commit()
        
    conn.close()


# --- AUTHENTICATION, FREE INVITES, & $20 GENESIS PAYWALL ---

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password_hash, ln_wallet_id FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
            session['username'] = username
            
            # LAZY MINTING: PROVISION MISSING VAULTS ON LOGIN
            wallet_id = user[1]
            if not wallet_id:
                try:
                    ln_url = os.getenv('LNBITS_URL')
                    if ln_url:
                        res = requests.post(
                            f"{ln_url}/api/v1/account",
                            json={"name": f"{username}_vault"},
                            timeout=5
                        )
                        if res.status_code in [200, 201]:
                            data = res.json()
                            admin_key = data.get("adminkey")
                            new_wallet_id = data.get("id")
                            cur.execute("UPDATE users SET ln_wallet_id = %s, ln_admin_key = %s WHERE username = %s", (new_wallet_id, admin_key, username))
                            conn.commit()
                            print(f"[*] Auto-provisioned missing financial vault for {username}.")
                except Exception as e:
                    print(f"Lazy minting failed for {username}: {e}")
            
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash('Invalid clearance credentials.', 'error')
            
    return render_template('login.html', title='Gateway')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('login.html', title='Gateway')

    data = request.get_json(silent=True) or request.form
    username = data.get('username')
    password = data.get('password')
    invite_key = data.get('invite_key')
    
    if not username or not password or not invite_key:
        flash('Missing required registration credentials.', 'error')
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 1. Validate Invite Key
    cur.execute("SELECT key, status, expires_at, generated_by FROM invite_keys WHERE key = %s", (invite_key,))
    invite_row = cur.fetchone()
    
    if not invite_row or invite_row[1] != 'unused':
        conn.close()
        flash('Invalid or claimed invite key.', 'error')
        return redirect(url_for('login'))
        
    expires_at = invite_row[2]
    generated_by = invite_row[3]
    
    current_ms = int(datetime.utcnow().timestamp() * 1000)
    if expires_at and current_ms > expires_at:
        cur.execute("UPDATE invite_keys SET status = 'expired' WHERE key = %s", (invite_key,))
        conn.commit()
        conn.close()
        flash('Access key has expired.', 'error')
        return redirect(url_for('login'))
        
    # 2. Guard against duplicate usernames
    cur.execute("SELECT username FROM users WHERE username = %s", (username,))
    if cur.fetchone():
        conn.close()
        flash('Username already taken.', 'error')
        return redirect(url_for('login'))

    # 3. Attempt LNbits Vault Provisioning early
    wallet_id = None
    admin_key = None
    try:
        ln_url = os.getenv('LNBITS_URL')
        if ln_url:
            res = requests.post(
                f"{ln_url}/api/v1/account",
                json={"name": f"{username}_vault"},
                timeout=5
            )
            if res.status_code in [200, 201]:
                data = res.json()
                wallet_id = data.get("id")
                admin_key = data.get("adminkey")
    except Exception as e:
        print(f"LNbits offline during registration: {e}")

    # 4. Hash Password & Create Basic Account (is_pro = FALSE)
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    try:
        cur.execute("""
            INSERT INTO users (username, display_name, password_hash, ln_wallet_id, ln_admin_key, invited_by, is_pro) 
            VALUES (%s, %s, %s, %s, %s, %s, FALSE)
        """, (username, username, hashed_pw, admin_key or wallet_id, admin_key, generated_by))
        
        cur.execute("UPDATE invite_keys SET status = 'used', used_by = %s WHERE key = %s", (username, invite_key))
        conn.commit()

    except Exception as e:
        conn.rollback()
        conn.close()
        flash(f'Database error: {str(e)}', 'error')
        return redirect(url_for('login'))
        
    conn.close()
    session['username'] = username
    session['is_first_login'] = True
    return redirect('/dashboard')

@app.route('/api/purchase/genesis_key', methods=['POST'])
def purchase_genesis_key():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing credentials.'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    if cur.fetchone():
        conn.close()
        return jsonify({'error': 'Username already taken.'}), 400
    conn.close()

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'StreetCode Genesis Access ($20 Door Fee)',
                        'description': 'Direct clearance for independent basic node'
                    },
                    'unit_amount': 2000,
                },
                'quantity': 1,
            }],
            mode='payment',
            client_reference_id=username,
            metadata={
                'purpose': 'genesis_purchase',
                'username': username,
                'password_hash': hashed_pw
            },
            success_url=request.host_url + 'login?registered=success',
            cancel_url=request.host_url + 'login?error=cancelled'
        )
        return jsonify({'checkout_url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/invite/generate', methods=['POST'])
def generate_invite():
    if 'username' not in session: 
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT is_pro, is_admin FROM users WHERE username = %s", (session['username'],))
    user_row = cur.fetchone()
    
    if not user_row or (not user_row[0] and not user_row[1]):
        conn.close()
        return jsonify({
            'error': 'Basic accounts cannot mint keys. Upgrade to Pro ($10/mo) in the Terminal to unlock key generation.'
        }), 403

    new_key = "METRO-" + os.urandom(4).hex().upper()
    expires_dt = datetime.utcnow() + timedelta(minutes=5)
    expires_ms = int(expires_dt.timestamp() * 1000)

    try:
        cur.execute("""
            INSERT INTO invite_keys (key, generated_by, creator, status, expires_at) 
            VALUES (%s, %s, %s, 'unused', %s)
        """, (new_key, session['username'], session['username'], expires_ms))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': str(e)}), 500

    conn.close()
    return jsonify({'key': new_key, 'expires_at': expires_dt.isoformat() + 'Z'})

# --- PASSWORD RECOVERY ENGINE ---

@app.route('/api/auth/reset-request', methods=['POST'])
def request_password_reset():
    email = request.json.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
        
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    
    if user:
        reset_token = uuid.uuid4().hex
        expires_at = int((datetime.utcnow() + timedelta(hours=1)).timestamp() * 1000)
        
        cur.execute("UPDATE users SET pwd_reset_token = %s, pwd_reset_expires = %s WHERE email = %s", 
                    (reset_token, expires_at, email))
        conn.commit()
        
        reset_link = f"{request.host_url}reset-password?token={reset_token}"
        email_body = f"""
        <h3>Street Code 101 - Security Protocol</h3>
        <p>A password reset has been requested for your node.</p>
        <p>Click the secure link below to reset your Gateway Passphrase:</p>
        <p><a href="{reset_link}">{reset_link}</a></p>
        <br>
        <p><i><strong>CRITICAL:</strong> Resetting your passphrase will not unlock your encrypted Vault. You will still need your physical 16-character Recovery Key to decrypt your historical messages once you log back in.</i></p>
        """
        
        threading.Thread(target=send_system_email, args=(email, "Node Password Reset Request", email_body)).start()
        
    conn.close()
    return jsonify({'status': 'success', 'message': 'If the email exists in our records, a secure link has been sent.'})

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_page():
    token = request.args.get('token') if request.method == 'GET' else request.form.get('token')
    if not token:
        flash('Invalid or missing security token.', 'error')
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, pwd_reset_expires FROM users WHERE pwd_reset_token = %s", (token,))
    user = cur.fetchone()
    
    if not user:
        conn.close()
        flash('Security token is invalid or has expired.', 'error')
        return redirect(url_for('login'))
        
    current_time = int(datetime.utcnow().timestamp() * 1000)
    if current_time > (user[1] or 0):
        cur.execute("UPDATE users SET pwd_reset_token = NULL, pwd_reset_expires = NULL WHERE pwd_reset_token = %s", (token,))
        conn.commit()
        conn.close()
        flash('Security token has expired.', 'error')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        if not new_password:
            conn.close()
            return "Password is required", 400
            
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')
        
        cur.execute("UPDATE users SET password_hash = %s, pwd_reset_token = NULL, pwd_reset_expires = NULL WHERE pwd_reset_token = %s", 
                    (hashed_pw, token))
        conn.commit()
        conn.close()
        
        flash('Passphrase successfully reset. You may now log in to the Gateway.', 'success')
        return redirect(url_for('login'))
        
    conn.close()
    from flask import render_template_string
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Reset Passphrase | Gateway</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { background: #0b1120; color: #f8fafc; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .box { background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(56,189,248,0.3); padding: 30px; border-radius: 12px; width: 90%; max-width: 400px; text-align: center; }
            input { width: 100%; padding: 12px; margin: 15px 0; box-sizing: border-box; background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.2); color: white; border-radius: 8px; }
            button { width: 100%; padding: 14px; background: #38bdf8; color: #042f40; border: none; font-weight: bold; border-radius: 8px; cursor: pointer; }
            h2 { margin-top: 0; color: #38bdf8; }
        </style>
    </head>
    <body>
        <div class="box">
            <h2>Establish New Passphrase</h2>
            <form method="POST" action="/reset-password">
                <input type="hidden" name="token" value="{{ token }}">
                <input type="password" name="password" placeholder="New Secure Passphrase" required>
                <button type="submit">Update & Seal</button>
            </form>
            <p style="font-size: 0.8rem; color: #94a3b8; margin-top: 20px;">Note: You will still need your physical 16-character Recovery Key to decrypt your historical vault messages.</p>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, token=token)
@app.route('/api/invites/ledger', methods=['GET'])
def get_invite_ledger():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT key, status, used_by FROM invite_keys WHERE generated_by = %s", (session['username'],))
        rows = cur.fetchall()
        conn.close()
        
        keys = [{'key': r[0], 'status': r[1], 'used_by': r[2]} for r in rows]
        return jsonify(keys)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- STREET CRED CALCULATOR ENGINE ---

def calculate_street_cred(username, conn=None):
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cur = conn.cursor()
    
    cur.execute("SELECT is_admin FROM users WHERE username = %s", (username,))
    admin_row = cur.fetchone()
    is_admin = admin_row[0] if admin_row else False
    
    # Master Admin Immunity: Always Square Business
    if is_admin or username == 'catch_flight':
        if close_conn: conn.close()
        return {
            'rank': 'Square Business 🤝',
            'score': 100,
            'total_votes': 0,
            'upvotes': 0,
            'downvotes': 0,
            'color': 'black'
        }
        
    cur.execute("SELECT vote_value, COUNT(*) FROM street_cred_votes WHERE target_username = %s GROUP BY vote_value", (username,))
    rows = cur.fetchall()
    
    upvotes = 0
    downvotes = 0
    for r in rows:
        if r[0] == 1:
            upvotes = r[1]
        elif r[0] == -1:
            downvotes = r[1]
            
    total_votes = upvotes + downvotes
    
    # Proof of Work Threshold: Less than 5 total votes defaults to "Alright"
    if total_votes < 5:
        rank = "Alright 😐"
        pct = 50 if total_votes == 0 else int((upvotes / total_votes) * 100)
        color = "white"
    else:
        pct = int((upvotes / total_votes) * 100)
        if pct >= 90:
            rank = "Square Business 🤝"
            color = "black"
        elif pct >= 75:
            rank = "A-1 💯"
            color = "blue"
        elif pct >= 50:
            rank = "Alright 😐"
            color = "white"
        elif pct >= 25:
            rank = "Shady 🐍"
            color = "gray"
        else:
            rank = "Rat 🐀"
            color = "red"
            
    if close_conn: conn.close()
    return {
        'rank': rank,
        'score': pct,
        'total_votes': total_votes,
        'upvotes': upvotes,
        'downvotes': downvotes,
        'color': color
    }


# --- STRIPE WEBHOOK HANDLER ---

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET')
        )
    except Exception as e:
        return str(e), 400

    event_id = event['id']
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("SELECT event_id FROM processed_webhooks WHERE event_id = %s", (event_id,))
        if cur.fetchone():
            return jsonify(success=True)

        if event['type'] == 'checkout.session.completed':
            session_obj = event['data']['object']
            metadata = session_obj.get('metadata', {})
            purpose = metadata.get('purpose')

            if purpose == 'genesis_purchase':
                username = metadata.get('username')
                pw_hash = metadata.get('password_hash')

                cur.execute("""
                    INSERT INTO users (username, display_name, password_hash, is_pro)
                    VALUES (%s, %s, %s, FALSE) ON CONFLICT (username) DO NOTHING
                """, (username, username, pw_hash))
                
                try:
                    ln_url = os.getenv('LNBITS_URL')
                    if ln_url:
                        res = requests.post(
                            f"{ln_url}/api/v1/account",
                            json={"name": f"{username}_vault"},
                            timeout=5
                        )
                        if res.status_code in [200, 201]:
                            data = res.json()
                            new_wallet_id = data.get('id')
                            new_admin_key = data.get('adminkey')
                            cur.execute("UPDATE users SET ln_wallet_id = %s, ln_admin_key = %s WHERE username = %s", (new_wallet_id, new_admin_key, username))
                except Exception as e:
                    print(f"LNbits offline during Genesis creation: {e}")

                conn.commit()
                print(f"[*] Genesis Account created for {username} via $20 Paywall.")

            elif purpose == 'pro_upgrade':
                username = metadata.get('username') or session_obj.get('client_reference_id')
                if username:
                    cur.execute("UPDATE users SET is_pro = TRUE WHERE username = %s", (username,))
                    conn.commit()
                    print(f"[*] Operator {username} upgraded to Pro Status.")

            elif purpose == 'fiat_sats_purchase':
                username = metadata.get('username')
                usd_amount = float(metadata.get('usd_amount', 10.0))
                
                try:
                    btc_res = requests.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd', timeout=5)
                    btc_price = btc_res.json()['bitcoin']['usd']
                    sats_to_credit = int((usd_amount / btc_price) * 100_000_000)
                    
                    cur.execute("SELECT ln_admin_key, ln_wallet_id FROM users WHERE username = %s", (username,))
                    u_row = cur.fetchone()
                    if u_row and (u_row[0] or u_row[1]):
                        user_key = u_row[0] or u_row[1]
                        treasury_key = os.getenv('LNBITS_ADMIN_KEY')
                        ln_url = os.getenv('LNBITS_URL')
                        
                        inv_res = requests.post(
                            f"{ln_url}/api/v1/payments",
                            headers={"X-Api-Key": user_key},
                            json={"out": False, "amount": sats_to_credit, "memo": f"Fiat Onramp Deposit (${usd_amount} USD)"},
                            timeout=5
                        )
                        if inv_res.status_code == 201:
                            bolt11 = inv_res.json().get('payment_request')
                            requests.post(
                                f"{ln_url}/api/v1/payments",
                                headers={"X-Api-Key": treasury_key},
                                json={"out": True, "bolt11": bolt11},
                                timeout=5
                            )
                            print(f"[*] Credited {sats_to_credit} sats to @{username} for ${usd_amount} USD deposit.")
                except Exception as e:
                    print(f"[-] Sats minting webhook error: {e}")

        cur.execute("INSERT INTO processed_webhooks (event_id) VALUES (%s)", (event_id,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Webhook database fault: {e}")
        return str(e), 500
    finally:
        conn.close()

    return jsonify(success=True)


# --- USER DIRECTORY & DASHBOARD ROUTING ---

@app.route('/api/users')
def api_users():
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, display_name, profile_pic, is_pro, is_admin FROM users")
    rows = cur.fetchall()
    
    users = []
    for r in rows:
        cred = calculate_street_cred(r[0], conn)
        users.append({
            'username': r[0],
            'display_name': r[1] or r[0],
            'profile_pic': r[2],
            'is_pro': r[3],
            'is_admin': r[4],
            'street_cred': cred
        })
    conn.close()
    return jsonify(users)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session: return redirect(url_for('login'))
    show_welcome = session.pop('is_first_login', False)
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_pro, is_admin, display_name FROM users WHERE username = %s", (session['username'],))
    row = cur.fetchone()
    is_pro = row[0] if row else False
    is_admin = row[1] if row else False
    display_name = (row[2] if row and row[2] else session['username'])
    conn.close()
    
    return render_template(
        'dashboard.html', 
        username=session['username'], 
        display_name=display_name,
        is_pro=is_pro, 
        is_admin=is_admin,
        show_welcome=show_welcome
    )


# --- CRYPTOGRAPHY ENGINE ---

@app.route('/api/crypto/keys', methods=['POST'])
def save_keys():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET public_key = %s, encrypted_private_key = %s WHERE username = %s", 
                (data['public_key'], data['encrypted_private_key'], session['username']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/crypto/my_keys')
def get_my_keys():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT public_key, encrypted_private_key FROM users WHERE username = %s", (session['username'],))
    keys = cur.fetchone()
    conn.close()
    if keys and keys[0] and keys[1]: return jsonify({'public_key': keys[0], 'encrypted_private_key': keys[1]})
    return jsonify({'error': 'Keys not found'}), 404

@app.route('/api/crypto/public_key/<username>')
def get_public_key(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM users WHERE username = %s", (username,))
    row = cur.fetchone()
    conn.close()
    if row and row[0]: return jsonify({'public_key': row[0]})
    return jsonify({'error': 'Not found'}), 404


# --- USER PROFILE, ALIASES, & STREET CRED VOTING ---

@app.route('/api/profile/<username>', methods=['GET', 'POST'])
def api_profile(username):
    if 'username' not in session: 
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    cur = conn.cursor()
    
    if request.method == 'POST':
        if session['username'] != username: 
            return jsonify({'error': 'Unauthorized'}), 403
            
        data = request.json
        if 'bio' in data: 
            cur.execute("UPDATE users SET bio = %s WHERE username = %s", (data['bio'], username))
        if 'profile_pic' in data: 
            cur.execute("UPDATE users SET profile_pic = %s WHERE username = %s", (data['profile_pic'], username))
        if 'display_name' in data:
            # If they submit empty string, it clears the alias
            val = data['display_name'].strip() if data['display_name'] else None
            cur.execute("UPDATE users SET display_name = %s WHERE username = %s", (val, username))
        if 'email' in data:
            val = data['email'].strip() if data['email'] else None
            cur.execute("UPDATE users SET email = %s WHERE username = %s", (val, username))
            
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

    # Fetch user data alongside reputation calculations
    cur.execute("""
        SELECT u.username, u.display_name, u.bio, u.profile_pic, u.ln_wallet_id, u.stripe_account, i.creator, u.is_pro, u.is_admin, u.email
        FROM users u
        LEFT JOIN invite_keys i ON i.used_by = u.username
        WHERE u.username = %s
    """, (username,))
    user = cur.fetchone()
    
    if user:
        # Pass connection to the street cred calculator so we don't open multiple db pools
        cred = calculate_street_cred(username, conn) 
        conn.close()
        return jsonify({
            'username': user[0], 
            'display_name': user[1] or user[0],  # Fallback to username if alias is null
            'bio': user[2] or "", 
            'profile_pic': user[3] or "",
            'ln_wallet_id': user[4],
            'stripe_account': user[5],
            'invited_by': user[6],
            'is_pro': user[7],
            'is_admin': user[8],
            'email': user[9] or "",
            'street_cred': cred
        })
        
    conn.close()
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/profile/<username>/vote', methods=['POST'])
def vote_street_cred(username):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    voter = session['username']
    
    if voter == username:
        return jsonify({'error': 'You cannot vote on your own node.'}), 400
        
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT is_admin FROM users WHERE username = %s", (username,))
    target_user = cur.fetchone()
    if not target_user:
        conn.close()
        return jsonify({'error': 'Target user not found.'}), 404
        
    if target_user[0] or username == 'catch_flight':
        conn.close()
        return jsonify({'error': 'Master Admin is immune to reputation votes.'}), 403
        
    data = request.json or {}
    vote_val = int(data.get('vote', 1)) # +1 or -1
    if vote_val not in [1, -1]:
        conn.close()
        return jsonify({'error': 'Invalid vote value.'}), 400
        
    cur.execute("""
        INSERT INTO street_cred_votes (voter, target_username, vote_value)
        VALUES (%s, %s, %s)
        ON CONFLICT (voter, target_username) 
        DO UPDATE SET vote_value = EXCLUDED.vote_value, timestamp = CURRENT_TIMESTAMP
    """, (voter, username, vote_val))
    
    conn.commit()
    cred = calculate_street_cred(username, conn)
    conn.close()
    
    return jsonify({'status': 'success', 'street_cred': cred})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    if 'photo' not in request.files: return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['photo']
    if file.filename == '': return jsonify({'error': 'No file selected'}), 400

    try:
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'png'
        filename = f"{uuid.uuid4().hex}_{session['username']}.{ext}"
        
        s3_client.upload_fileobj(
            file,
            BUCKET_NAME,
            filename,
            ExtraArgs={'ContentType': file.content_type}
        )
        
        endpoint = os.getenv('AWS_ENDPOINT_URL').rstrip('/')
        url = f"{endpoint}/{BUCKET_NAME}/{filename}"
        return jsonify({'url': url})
        
    except Exception as e:
        print(f"MinIO Upload Error: {e}")
        return jsonify({'error': 'Failed to route image to sovereign vault.'}), 500


# --- SOCIAL FEED, PURGING, & USER TRANSMISSIONS ---

@app.route('/api/feed', methods=['GET', 'POST'])
def api_feed():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    
    if request.method == 'POST':
        data = request.json
        cur.execute("INSERT INTO posts (username, content, image_url, is_wall_post) VALUES (%s, %s, %s, FALSE)", 
                    (session['username'], data.get('content'), data.get('image_url')))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

    cur.execute("""
        SELECT p.id, p.username, p.content, p.image_url, u.profile_pic, u.display_name, u.is_pro, u.is_admin 
        FROM posts p 
        JOIN users u ON p.username = u.username 
        WHERE p.is_wall_post = FALSE 
        ORDER BY p.id DESC LIMIT 50
    """)
    posts = []
    for row in cur.fetchall():
        post_id = row[0]
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = FALSE", (post_id,))
        likes = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = TRUE", (post_id,))
        dislikes = cur.fetchone()[0]
        cur.execute("SELECT username, content FROM post_comments WHERE post_id = %s ORDER BY id ASC", (post_id,))
        comments = cur.fetchall()
        cred = calculate_street_cred(row[1], conn)
        posts.append({
            'id': post_id, 
            'username': row[1], 
            'display_name': row[5] or row[1],
            'content': row[2], 
            'image_url': row[3], 
            'profile_pic': row[4], 
            'is_pro': row[6],
            'is_admin': row[7],
            'street_cred': cred,
            'likes_count': likes, 
            'dislikes_count': dislikes, 
            'comments': comments
        })
    conn.close()
    return jsonify(posts)

@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    current_user = session['username']
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT username FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    if not post:
        conn.close()
        return jsonify({'error': 'Post not found'}), 404
        
    post_owner = post[0]
    
    cur.execute("SELECT is_admin FROM users WHERE username = %s", (current_user,))
    is_admin = cur.fetchone()[0]
    
    if post_owner != current_user and not is_admin:
        conn.close()
        return jsonify({'error': 'Forbidden: You can only purge your own transmissions.'}), 403
        
    cur.execute("DELETE FROM post_likes WHERE post_id = %s", (post_id,))
    cur.execute("DELETE FROM post_comments WHERE post_id = %s", (post_id,))
    cur.execute("DELETE FROM posts WHERE id = %s", (post_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message': 'Transmission purged.'})

@app.route('/api/profile/<username>/transmissions')
def get_user_transmissions(username):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT p.id, p.username, p.content, p.image_url, u.profile_pic, u.display_name, u.is_pro, u.is_admin
        FROM posts p
        JOIN users u ON p.username = u.username
        WHERE p.username = %s AND p.is_wall_post = FALSE
        ORDER BY p.id DESC
    """, (username,))
    posts = []
    for row in cur.fetchall():
        post_id = row[0]
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = FALSE", (post_id,))
        likes = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = TRUE", (post_id,))
        dislikes = cur.fetchone()[0]
        cur.execute("SELECT username, content FROM post_comments WHERE post_id = %s ORDER BY id ASC", (post_id,))
        comments = cur.fetchall()
        cred = calculate_street_cred(row[1], conn)
        posts.append({
            'id': post_id,
            'username': row[1],
            'display_name': row[5] or row[1],
            'content': row[2],
            'image_url': row[3],
            'profile_pic': row[4],
            'is_pro': row[6],
            'is_admin': row[7],
            'street_cred': cred,
            'likes_count': likes,
            'dislikes_count': dislikes,
            'comments': comments
        })
    conn.close()
    return jsonify(posts)

@app.route('/api/feed/<int:post_id>/<action>', methods=['POST'])
def api_feed_interact(post_id, action):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    if action == 'like':
        cur.execute("INSERT INTO post_likes (post_id, username, is_dislike) VALUES (%s, %s, FALSE)", (post_id, session['username']))
    elif action == 'dislike':
        cur.execute("INSERT INTO post_likes (post_id, username, is_dislike) VALUES (%s, %s, TRUE)", (post_id, session['username']))
    elif action == 'comment':
        cur.execute("INSERT INTO post_comments (post_id, username, content) VALUES (%s, %s, %s)", (post_id, session['username'], request.json.get('content')))
    elif action == 'share':
        cur.execute("SELECT content, image_url FROM posts WHERE id = %s", (post_id,))
        og_post = cur.fetchone()
        if og_post:
            new_content = f"{request.json.get('caption', '')}\n\n[Shared]: {og_post[0]}"
            cur.execute("INSERT INTO posts (username, content, image_url, is_wall_post, target_username) VALUES (%s, %s, %s, TRUE, %s)", 
                        (session['username'], new_content, og_post[1], session['username']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/profile/<username>/posts', methods=['GET', 'POST'])
def api_profile_posts(username):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    
    if request.method == 'POST':
        data = request.json
        cur.execute("INSERT INTO posts (username, target_username, content, image_url, is_wall_post) VALUES (%s, %s, %s, %s, TRUE)", 
                    (session['username'], username, data.get('content'), data.get('image_url')))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

    cur.execute("SELECT p.id, p.username, p.content, p.image_url FROM posts p WHERE p.target_username = %s AND p.is_wall_post = TRUE ORDER BY p.id DESC LIMIT 50", (username,))
    posts = []
    for row in cur.fetchall():
        post_id = row[0]
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = FALSE", (post_id,))
        likes = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = TRUE", (post_id,))
        dislikes = cur.fetchone()[0]
        cur.execute("SELECT username, content FROM post_comments WHERE post_id = %s ORDER BY id ASC", (post_id,))
        comments = cur.fetchall()
        posts.append({'id': post_id, 'username': row[1], 'content': row[2], 'image_url': row[3], 'likes_count': likes, 'dislikes_count': dislikes, 'comments': comments})
    conn.close()
    return jsonify(posts)

@app.route('/api/profile/posts/<int:post_id>/<action>', methods=['POST'])
def api_wall_interact(post_id, action):
    return api_feed_interact(post_id, action)
# --- DIRECT MESSAGING: READ RECEIPTS ---

@app.route('/api/messages/read', methods=['POST'])
def mark_messages_read():
    if 'username' not in session: 
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.json or {}
    sender_to_mark = data.get('sender')
    
    if not sender_to_mark: 
        return jsonify({'error': 'Missing sender target'}), 400
        
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Mark all unread messages sent BY the target TO the current user as read
    cur.execute("""
        UPDATE messages 
        SET is_read = TRUE 
        WHERE sender = %s AND receiver = %s AND is_read = FALSE
    """, (sender_to_mark, session['username']))
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success'})


# --- GROUP WORKSPACES ---

@app.route('/api/groups/create', methods=['POST'])
def create_group():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    name = request.json.get('name')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO group_chats (name, creator) VALUES (%s, %s) RETURNING id", (name, session['username']))
    group_id = cur.fetchone()[0]
    cur.execute("INSERT INTO group_members (group_id, username) VALUES (%s, %s)", (group_id, session['username']))
    conn.commit()
    conn.close()
    return jsonify({'id': group_id})

@app.route('/api/groups/list')
def list_groups():
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT g.id, g.name, g.creator 
        FROM group_chats g 
        JOIN group_members m ON g.id = m.group_id 
        WHERE m.username = %s 
        ORDER BY g.created_at DESC
    """, (session['username'],))
    groups = [{'id': r[0], 'name': r[1], 'creator': r[2]} for r in cur.fetchall()]
    conn.close()
    return jsonify(groups)

@app.route('/api/groups/<int:group_id>/add_member', methods=['POST'])
def add_group_member(group_id):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    target_user = request.json.get('username')
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT creator FROM group_chats WHERE id = %s", (group_id,))
    res = cur.fetchone()
    if not res or res[0] != session['username']:
        conn.close()
        return jsonify({'error': 'Only creator can add members'}), 403

    try:
        cur.execute("INSERT INTO group_members (group_id, username) VALUES (%s, %s)", (group_id, target_user))
        conn.commit()
    except: pass
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/groups/<int:group_id>/members')
def get_group_members(group_id):
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM group_members WHERE group_id = %s", (group_id,))
    members = [r[0] for r in cur.fetchall()]
    conn.close()
    return jsonify(members)

@app.route('/api/groups/<int:group_id>/messages')
def get_group_messages(group_id):
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT sender, text FROM group_messages WHERE group_id = %s ORDER BY id ASC", (group_id,))
    msgs = [{'sender': r[0], 'text': r[1]} for r in cur.fetchall()]
    conn.close()
    return jsonify(msgs)


# --- FINANCIALS: GROUP POOLS ---

@app.route('/api/groups/<int:group_id>/pools/create', methods=['POST'])
def create_group_pool(group_id):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    name = request.json.get('name')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO money_pools (group_id, name, creator) VALUES (%s, %s, %s)", (group_id, name, session['username']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/groups/<int:group_id>/pools')
def get_group_pools(group_id):
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, creator, total_escrow_cents, status, released_to FROM money_pools WHERE group_id = %s ORDER BY id DESC", (group_id,))
    pools = [{'id': r[0], 'name': r[1], 'creator': r[2], 'total_escrow_cents': r[3], 'status': r[4], 'released_to': r[5]} for r in cur.fetchall()]
    conn.close()
    return jsonify(pools)

@app.route('/api/pools/<int:pool_id>/contribute', methods=['POST'])
def contribute_to_pool(pool_id):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    amount_dollars = float(request.json.get('amount'))
    amount_cents = int(amount_dollars * 100)
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO pool_contributions (pool_id, username, amount_cents) VALUES (%s, %s, %s)", (pool_id, session['username'], amount_cents))
    cur.execute("UPDATE money_pools SET total_escrow_cents = total_escrow_cents + %s WHERE id = %s", (amount_cents, pool_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/pools/<int:pool_id>/release', methods=['POST'])
def release_pool(pool_id):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    receiver = request.json.get('receiver')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT creator, status FROM money_pools WHERE id = %s", (pool_id,))
    pool = cur.fetchone()
    
    if not pool or pool[0] != session['username'] or pool[1] != 'active':
        conn.close()
        return jsonify({'error': 'Only creator can release active pools'}), 403

    cur.execute("UPDATE money_pools SET status = 'released', released_to = %s WHERE id = %s", (receiver, pool_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})


# --- FINANCIALS: 1-ON-1 ESCROW & STRIPE ---

@app.route('/api/escrow/create', methods=['POST'])
def create_escrow():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    
    try:
        amount_sats = int(data['amount'])
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount format'}), 400

    if amount_sats <= 0:
        return jsonify({'error': 'Amount must be strictly greater than zero.'}), 400
    if amount_sats > 100000000:
        return jsonify({'error': 'Amount exceeds platform maximum.'}), 400
        
    receiver = data['receiver']
    sender = session['username']
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT ln_wallet_id FROM users WHERE username = %s", (sender,))
        sender_wallet = cur.fetchone()[0]
        
        treasury_key = os.getenv('LNBITS_ADMIN_KEY')
        inv_res = requests.post(
            f"{os.getenv('LNBITS_URL')}/api/v1/payments",
            headers={"X-Api-Key": treasury_key},
            json={"out": False, "amount": amount_sats, "memo": f"Escrow Lock: {sender} to {receiver}"}
        )
        if inv_res.status_code != 201:
            return jsonify({'error': 'Platform Treasury unavailable'}), 500
        bolt11 = inv_res.json().get('payment_request')
        
        pay_res = requests.post(
            f"{os.getenv('LNBITS_URL')}/api/v1/payments",
            headers={"X-Api-Key": sender_wallet},
            json={"out": True, "bolt11": bolt11}
        )
        if pay_res.status_code != 201:
            return jsonify({'error': 'Insufficient funds in sender Vault'}), 400
        
        cur.execute("INSERT INTO escrow_transactions (sender, receiver, amount_cents, status) VALUES (%s, %s, %s, 'held_in_escrow') RETURNING id", 
                    (sender, receiver, amount_sats))
        tx_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({'id': tx_id, 'status': 'held_in_escrow'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/escrow/list')
def list_escrow():
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, sender, receiver, amount_cents, status FROM escrow_transactions WHERE sender = %s OR receiver = %s ORDER BY id DESC", 
                (session['username'], session['username']))
    txs = [{'id': r[0], 'sender': r[1], 'receiver': r[2], 'amount_cents': r[3], 'status': r[4]} for r in cur.fetchall()]
    conn.close()
    return jsonify(txs)

@app.route('/api/stripe/onramp', methods=['POST'])
def stripe_onramp():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    try:
        onramp_session = stripe.crypto.OnrampSession.create(
            destination_currency="btc",
            destination_network="lightning",
            destination_details={"lightning": {"node_id": "placeholder"}},
            amount="50.00", source_currency="usd"
        )
        return jsonify({'client_secret': onramp_session.client_secret})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/stripe/checkout', methods=['POST'])
def stripe_checkout():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = request.json
        purpose = data.get('purpose', 'fund_escrow')
        amount_cents = int(float(data.get('amount', 9.99)) * 100)
        
        metadata = {'username': session['username'], 'purpose': purpose}
        if purpose == 'fund_escrow':
            metadata['escrow_id'] = data.get('id', '')
            product_name = f'Escrow Funding TX-{data.get("id", "Unknown")}'
        else:
            product_name = 'StreetCode Pro Authorization'

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price_data': {'currency': 'usd', 'product_data': {'name': product_name}, 'unit_amount': amount_cents}, 'quantity': 1}],
            mode='payment',
            metadata=metadata,
            success_url=request.host_url + 'dashboard?payment=success',
            cancel_url=request.host_url + 'dashboard?payment=cancelled'
        )
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# --- FINANCIALS: ESCROW RELEASE ENGINE & FIAT SATS PURCHASE ---

@app.route('/api/escrow/release', methods=['POST'])
def release_escrow():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.json or {}
    tx_id = data.get('id')
    if not tx_id:
        return jsonify({'error': 'Missing transaction ID'}), 400
        
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT sender, receiver, amount_cents, status 
        FROM escrow_transactions 
        WHERE id = %s
    """, (tx_id,))
    tx = cur.fetchone()
    
    if not tx:
        conn.close()
        return jsonify({'error': 'Escrow transaction not found'}), 404
        
    sender, receiver, amount_sats, status = tx[0], tx[1], tx[2], tx[3]
    
    if sender != session['username']:
        cur.execute("SELECT is_admin FROM users WHERE username = %s", (session['username'],))
        admin_row = cur.fetchone()
        if not admin_row or not admin_row[0]:
            conn.close()
            return jsonify({'error': 'Only the escrow sender can release funds.'}), 403
            
    if status != 'held_in_escrow':
        conn.close()
        return jsonify({'error': f'Escrow cannot be released. Status is {status}.'}), 400

    fee_sats = int(amount_sats * 0.05)
    payout_sats = amount_sats - fee_sats

    cur.execute("SELECT ln_admin_key, ln_wallet_id FROM users WHERE username = %s", (receiver,))
    rec_row = cur.fetchone()
    
    if not rec_row or not (rec_row[0] or rec_row[1]):
        conn.close()
        return jsonify({'error': 'Receiver does not have an active Lightning Vault.'}), 400
        
    receiver_key = rec_row[0] or rec_row[1]
    treasury_admin_key = os.getenv('LNBITS_ADMIN_KEY')
    ln_url = os.getenv('LNBITS_URL')

    try:
        inv_res = requests.post(
            f"{ln_url}/api/v1/payments",
            headers={"X-Api-Key": receiver_key},
            json={"out": False, "amount": payout_sats, "memo": f"Escrow Release TX-{tx_id}"},
            timeout=5
        )
        if inv_res.status_code != 201:
            conn.close()
            return jsonify({'error': 'Failed to generate receiver payout invoice.'}), 500
            
        bolt11 = inv_res.json().get('payment_request')

        pay_res = requests.post(
            f"{ln_url}/api/v1/payments",
            headers={"X-Api-Key": treasury_admin_key},
            json={"out": True, "bolt11": bolt11},
            timeout=5
        )
        if pay_res.status_code != 201:
            conn.close()
            return jsonify({'error': 'Treasury payout routing failed.'}), 500

        cur.execute("UPDATE escrow_transactions SET status = 'released_to_receiver' WHERE id = %s", (tx_id,))
        cur.execute("INSERT INTO platform_treasury (source_escrow_id, amount_collected) VALUES (%s, %s)", (tx_id, fee_sats))
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success', 
            'message': f'Escrow released. {payout_sats} sats sent to @{receiver}. Fee: {fee_sats} sats.'
        })
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': f'Escrow release engine fault: {str(e)}'}), 500


@app.route('/api/wallet/buy-sats', methods=['POST'])
def buy_sats_checkout():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.json or {}
    try:
        usd_amount = float(data.get('usd_amount', 10.00))
    except (ValueError, TypeError):
        usd_amount = 10.00

    if usd_amount < 1.00:
        return jsonify({'error': 'Minimum purchase amount is $1.00 USD.'}), 400

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'Bitcoin Satoshis Deposit (${usd_amount:.2f} USD)',
                        'description': f'Direct Lightning Vault funding for @{session["username"]}'
                    },
                    'unit_amount': int(usd_amount * 100),
                },
                'quantity': 1,
            }],
            mode='payment',
            client_reference_id=session['username'],
            metadata={
                'purpose': 'fiat_sats_purchase',
                'username': session['username'],
                'usd_amount': str(usd_amount)
            },
            success_url=request.host_url + 'dashboard?deposit=success',
            cancel_url=request.host_url + 'dashboard?deposit=cancelled'
        )
        return jsonify({'checkout_url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- FINANCIALS: LIGHTNING CRYPTO VAULT & DIRECT TRANSFERS ---

@app.route('/api/wallet/balance')
def api_wallet_balance():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT ln_admin_key, ln_wallet_id FROM users WHERE username = %s", (session['username'],))
        u_row = cur.fetchone()
        conn.close()
        
        if not u_row or not (u_row[0] or u_row[1]): return jsonify({'status': 'mock_vault_active'})
        
        api_key = u_row[0] or u_row[1]
        headers = {"X-Api-Key": api_key}
        res = requests.get(f"{os.getenv('LNBITS_URL')}/api/v1/wallet", headers=headers, timeout=5)
        if res.status_code == 200:
            return jsonify({'balance_sats': res.json().get('balance', 0) // 1000})
        return jsonify({'error': 'Node rejected connection'}), 500
    except Exception as e:
        return jsonify({'error': 'Network timeout'}), 500

@app.route('/api/wallet/invoice', methods=['POST'])
def api_wallet_invoice():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    amount_sats = request.json.get('amount_sats')
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ln_admin_key, ln_wallet_id FROM users WHERE username = %s", (session['username'],))
    u_row = cur.fetchone()
    conn.close()
    
    api_key = u_row[0] or u_row[1] if u_row else None
    if not api_key:
        return jsonify({'error': 'No active vault key found'}), 400

    headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
    payload = {"out": False, "amount": amount_sats, "memo": f"Direct request to {session['username']}"}
    res = requests.post(f"{os.getenv('LNBITS_URL')}/api/v1/payments", json=payload, headers=headers)
    
    if res.status_code == 201:
        return jsonify({'payment_request': res.json().get('payment_request')})
    return jsonify({'error': 'Failed to generate invoice'}), 500

@app.route('/api/wallet/pay', methods=['POST'])
def api_wallet_pay():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    bolt11 = request.json.get('bolt11')
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ln_admin_key, ln_wallet_id FROM users WHERE username = %s", (session['username'],))
    u_row = cur.fetchone()
    conn.close()
    
    api_key = u_row[0] or u_row[1] if u_row else None
    if not api_key:
        return jsonify({'error': 'No active vault key found'}), 400

    headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
    payload = {"out": True, "bolt11": bolt11}
    res = requests.post(f"{os.getenv('LNBITS_URL')}/api/v1/payments", json=payload, headers=headers)
    
    if res.status_code == 201:
        return jsonify({'status': 'success'})
    return jsonify({'error': 'Payment routing failed or insufficient funds'}), 400

@app.route('/api/wallet/transfer', methods=['POST'])
def api_wallet_transfer():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    target_username = data.get('target_username')
    amount_sats = data.get('amount_sats')

    if not target_username or not amount_sats:
        return jsonify({'error': 'Missing parameters'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ln_admin_key, ln_wallet_id FROM users WHERE username = %s", (session['username'],))
    sender_row = cur.fetchone()
    cur.execute("SELECT ln_admin_key, ln_wallet_id FROM users WHERE username = %s", (target_username,))
    target_row = cur.fetchone()
    conn.close()

    if not sender_row or not (sender_row[0] or sender_row[1]):
        return jsonify({'error': 'Your node does not have an active financial vault.'}), 400
    if not target_row or not (target_row[0] or target_row[1]):
        return jsonify({'error': 'Target operator does not have an active financial vault.'}), 400

    sender_key = sender_row[0] or sender_row[1]
    target_key = target_row[0] or target_row[1]

    headers_target = {"X-Api-Key": target_key, "Content-Type": "application/json"}
    payload_target = {"out": False, "amount": amount_sats, "memo": f"Direct Transfer from {session['username']}"}
    inv_res = requests.post(f"{os.getenv('LNBITS_URL')}/api/v1/payments", json=payload_target, headers=headers_target)
    
    if inv_res.status_code != 201:
        return jsonify({'error': 'Failed to route destination invoice.'}), 500
    bolt11 = inv_res.json().get('payment_request')

    headers_sender = {"X-Api-Key": sender_key, "Content-Type": "application/json"}
    payload_sender = {"out": True, "bolt11": bolt11}
    pay_res = requests.post(f"{os.getenv('LNBITS_URL')}/api/v1/payments", json=payload_sender, headers=headers_sender)

    if pay_res.status_code == 201:
        return jsonify({'status': 'success', 'message': 'Capital routed successfully.'})
    else:
        return jsonify({'error': 'Insufficient funds or routing failure.'}), 400

# --- WEB PUSH SUBSCRIPTIONS ---

@app.route('/api/push/subscribe', methods=['POST'])
def push_subscribe():
    if 'username' not in session: 
        return jsonify({'error': 'Unauthorized'}), 401
        
    sub_info = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        sub_str = json.dumps(sub_info)
        cur.execute("SELECT id FROM push_subscriptions WHERE username = %s AND subscription_info = %s", (session['username'], sub_str))
        if not cur.fetchone():
            cur.execute("INSERT INTO push_subscriptions (username, subscription_info) VALUES (%s, %s)", 
                        (session['username'], sub_str))
            conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


# --- REAL-TIME MESH (WEBSOCKETS) & BACKGROUND WORKERS ---

async def broadcast_presence():
    online_users = list(connected_clients.keys())
    payload = json.dumps({"is_presence": True, "online_users": online_users})
    disconnected = []
    for ws in connected_clients.values():
        try:
            await ws.send(payload)
        except:
            disconnected.append(ws)
    for ws in disconnected:
        for u, client_ws in list(connected_clients.items()):
            if ws == client_ws: del connected_clients[u]

async def ws_handler(websocket, path=None):
    username = None
    try:
        async for message in websocket:
            data = json.loads(message)
            
            if "username" in data and len(data) == 1:
                username = data["username"]
                connected_clients[username] = websocket
                await broadcast_presence()
                
                conn = get_db_connection()
                cur = conn.cursor()
                
                # Fetching timestamps and is_read status for UI Inbox sorting
                cur.execute("""
                    SELECT id, sender, receiver, text, timestamp, is_read 
                    FROM messages 
                    WHERE sender = %s OR receiver = %s 
                    ORDER BY timestamp ASC
                """, (username, username))
                
                history = [{
                    "id": r[0], 
                    "sender": r[1], 
                    "receiver": r[2], 
                    "text": r[3], 
                    "timestamp": r[4].isoformat() if hasattr(r[4], 'isoformat') else str(r[4]).replace(' ', 'T'), 
                    "is_read": bool(r[5])
                } for r in cur.fetchall()]
                
                conn.close()
                await websocket.send(json.dumps({"is_history": True, "history": history}))
                continue

            if "group_id" in data and "text" in data:
                group_id = data["group_id"]
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO group_messages (group_id, sender, text) VALUES (%s, %s, %s)", (group_id, username, data["text"]))
                cur.execute("SELECT username FROM group_members WHERE group_id = %s", (group_id,))
                members = [r[0] for r in cur.fetchall()]
                conn.commit()
                conn.close()
                
                payload = json.dumps({"group_id": group_id, "sender": username, "text": data["text"]})
                for member in members:
                    if member in connected_clients:
                        await connected_clients[member].send(payload)
                continue

            if data.get("is_typing"):
                receiver = data.get("receiver")
                if receiver in connected_clients:
                    await connected_clients[receiver].send(json.dumps({"is_typing": True, "sender": username}))
                continue

            if "receiver" in data and "text" in data:
                receiver = data["receiver"]
                text = data["text"]
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO messages (sender, receiver, text) VALUES (%s, %s, %s)", (username, receiver, text))
                conn.commit()
                conn.close()
                
                if receiver in connected_clients:
                    await connected_clients[receiver].send(json.dumps({"sender": username, "receiver": receiver, "text": text}))

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if username in connected_clients:
            del connected_clients[username]
            await broadcast_presence()

def run_escrow_expiration_janitor():
    while True:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE escrow_transactions 
                SET status = 'refunded_to_sender' 
                WHERE status = 'held_in_escrow' AND created_at < NOW() - INTERVAL '24 hours'
            """)
            conn.commit()
            conn.close()
        except: pass
        import time
        time.sleep(3600)

def run_flask():
    try: app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    except Exception as e: print(f"❌ PORT BIND FAULT: {e}")

async def run_ws(port):
    print(f"🚀 Secure Mesh Binding to Port {port}")
    async with websockets.serve(ws_handler, "0.0.0.0", port): 
        await asyncio.Future()

# --- INITIALIZATION & IGNITION ---

with app.app_context():
    init_db()
    init_master_admin()

if __name__ == '__main__':
    mode = os.getenv("RUN_MODE", "LOCAL")
    
    threading.Thread(target=run_escrow_expiration_janitor, daemon=True).start()

    if mode == "WEBSOCKET":
        port = int(os.getenv("PORT", 5001))
        asyncio.run(run_ws(port))
    else:
        print("Launching Phase 3 E2EE Framework Core (Local Sandbox)...")
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()
        asyncio.run(run_ws(5001))
