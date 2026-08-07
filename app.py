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
import filetype
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from datetime import datetime, timedelta
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
# Tell Flask it is behind a secure Nginx proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

import os
# --- SESSION & PAYLOAD HARDENING ---
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # Hard limit: 50MB max payload size
app.config['SESSION_COOKIE_HTTPONLY'] = True # Block JS from reading cookies (XSS protection)
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# KILL SWITCH: Randomizing the secret key auto-wipes all active user sessions when the server reboots.
app.secret_key = os.urandom(24)
CORS(app)

# --- IN-MEMORY RATE LIMITING ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)

# --- SECURITY HEADERS ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Only enforce strict HTTPS memory if we are in production to prevent local testing lockouts
    if os.getenv('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

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
raw_endpoint = os.getenv('AWS_ENDPOINT_URL', '')
# Force HTTP and strip HTTPS if routing to the local loopback
aws_endpoint = raw_endpoint.replace('https://', 'http://') if '127.0.0.1' in raw_endpoint else raw_endpoint

s3_client = boto3.client(
    's3',
    endpoint_url=aws_endpoint,
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    config=Config(signature_version='s3v4'),
    region_name=os.getenv('AWS_REGION', 'us-east-1'),
    use_ssl=False if '127.0.0.1' in aws_endpoint else True
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
    
    # Run Safe Migrations for New Columns (Aliases, Email, Admin, Street Cred, Native Wallet)
    new_columns = [
        ("email", "VARCHAR(150) UNIQUE"),
        ("is_email_verified", "BOOLEAN DEFAULT FALSE"),
        ("email_verify_token", "VARCHAR(100)"),
        ("pwd_reset_token", "VARCHAR(100)"),
        ("pwd_reset_expires", "BIGINT"),
        ("display_name", "VARCHAR(50)"),
        ("reputation_score", "INTEGER DEFAULT 0"),
        ("is_admin", "BOOLEAN DEFAULT FALSE"),
        ("wallet_balance", "INTEGER DEFAULT 0")
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

    # 11. Concierge Cashout Requests
    cur.execute('''
        CREATE TABLE IF NOT EXISTS cashout_requests (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            amount_coins INTEGER NOT NULL,
            payout_method VARCHAR(50) NOT NULL,
            payout_address TEXT NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 12. Notification Center (The Pager)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            type VARCHAR(50) NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 13. Unified Transaction Ledger
    cur.execute('''
        CREATE TABLE IF NOT EXISTS wallet_transactions (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            amount INTEGER NOT NULL,
            tx_type VARCHAR(20) NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 14. Black Market Commerce
    cur.execute('''
        CREATE TABLE IF NOT EXISTS market_items (
            id SERIAL PRIMARY KEY,
            seller VARCHAR(50) NOT NULL,
            title VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            price_coins INTEGER NOT NULL,
            image_url TEXT,
            status VARCHAR(20) DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

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
    
    # The Central Bank Wallet Balance (1 Billion Coins)
    master_balance = 1000000000
    
    if not existing_user:
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(admin_pass.encode('utf-8'), salt).decode('utf-8')
        
        cur.execute("""
            INSERT INTO users (username, password_hash, is_pro, is_admin, email, is_email_verified, wallet_balance) 
            VALUES (%s, %s, TRUE, TRUE, 'admin@streetcode101.com', TRUE, %s)
        """, (admin_user, hashed_pw, master_balance))
        
        # Log the initial genesis mint for a new admin
        cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'deposit', 'Central Bank Genesis Mint')", (admin_user, master_balance))
        conn.commit()
        print(f"[*] Master Admin '{admin_user}' Auto-Provisioned with Central Bank Vault ({master_balance} Coins).")
    else:
        # Guarantee existing admin account is upgraded with fail-safes
        cur.execute("""
            UPDATE users 
            SET is_admin = TRUE, is_pro = TRUE, email = 'admin@streetcode101.com', is_email_verified = TRUE 
            WHERE username = %s
        """, (admin_user,))
        
        # Check if the Master Admin has EVER received the Genesis Mint in the ledger
        cur.execute("SELECT id FROM wallet_transactions WHERE username = %s AND description = 'Central Bank Genesis Mint'", (admin_user,))
        has_genesis_mint = cur.fetchone()
        
        if not has_genesis_mint:
            # First time running the new logic: Set balance to 1 Billion and log it so it NEVER happens again
            cur.execute("UPDATE users SET wallet_balance = %s WHERE username = %s", (master_balance, admin_user))
            cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'deposit', 'Central Bank Genesis Mint')", (admin_user, master_balance))
            print(f"[*] Master Admin '{admin_user}' Vault adjusted to Genesis Balance of {master_balance} Coins.")
            
        conn.commit()
        
    conn.close()


# --- AUTHENTICATION, FREE INVITES, & $20 GENESIS PAYWALL ---

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
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
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash('Invalid clearance credentials.', 'error')
            
    return render_template('login.html', title='Gateway')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
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

    # 3. Hash Password & Create Proprietary Account (is_pro = FALSE)
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    try:
        cur.execute("""
            INSERT INTO users (username, display_name, password_hash, invited_by, is_pro) 
            VALUES (%s, %s, %s, %s, FALSE)
        """, (username, username, hashed_pw, generated_by))
        
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

@app.route('/terms')
def terms_page():
    from flask import render_template_string
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Terms of Service & AUP | Street Code 101</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
            body { background: #0b1120; color: #cbd5e1; font-family: 'Inter', sans-serif; margin: 0; padding: 40px 20px; line-height: 1.6; display: flex; justify-content: center; }
            .terms-container { max-width: 750px; background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(56,189,248,0.3); padding: 40px; border-radius: 16px; box-shadow: 0 10px 40px rgba(0,0,0,0.8); }
            h1 { color: #38bdf8; font-size: 1.8rem; margin-top: 0; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid rgba(56,189,248,0.2); padding-bottom: 15px; }
            h2 { color: #f8fafc; font-size: 1.1rem; margin-top: 30px; margin-bottom: 10px; text-transform: uppercase; }
            p, li { font-size: 0.95rem; color: #cbd5e1; }
            ul { padding-left: 20px; }
            strong { color: #f8fafc; }
            .back-btn { display: inline-block; margin-top: 30px; padding: 10px 20px; background: #38bdf8; color: #0f172a; text-decoration: none; font-weight: bold; border-radius: 8px; }
            .back-btn:hover { background: #0ea5e9; color: white; }
        </style>
    </head>
    <body>
        <div class="terms-container">
            <h1>Terms of Service & AUP</h1>
            <p style="font-size:0.85rem; color:#94a3b8;"><i>Effective Date: August 2026</i></p>
            
            <h2>1. Cryptographic Architecture & Zero-Knowledge Disclaimer</h2>
            <p>Street Code 101 operates on a client-side, Zero-Knowledge End-to-End Encryption (E2EE) protocol. Private Direct Messages (DMs) and Gang Chat transmissions are encrypted on the user's local device prior to network routing.</p>
            <ul>
                <li><strong>No Server Inspection:</strong> The Platform operator does not possess, store, or maintain central private keys, decryption algorithms, or backdoors capable of inspecting encrypted user communications.</li>
                <li><strong>Absence of Monitoring Capacity:</strong> Because private messages are mathematically unreadable by the Platform, the Platform cannot moderate, filter, vet, or monitor private communications.</li>
                <li><strong>User Liability:</strong> Users assume 100% legal liability for all text, files, images, code, or intel transmitted via encrypted channels. The Platform is entirely hold-harmless for any illegal, infringing, or tortious activity occurring within E2EE sessions.</li>
            </ul>

            <h2>2. Key Stewardship & Account Loss</h2>
            <p>Users are solely responsible for maintaining the confidentiality of their Vault Passphrase and physical 16-character Recovery Key.</p>
            <ul>
                <li><strong>Unrecoverable Credentials:</strong> The Platform cannot reset lost Vault Passphrases or decrypt historical vault messages if a user loses their passphrase and recovery key.</li>
                <li><strong>Session Termination:</strong> Automated safety systems will terminate inactive sessions (10-minute idle threshold) and lock vault data. The Platform is not responsible for data loss resulting from automated security terminations.</li>
            </ul>

            <h2>3. StreetCoins & Treasury Policy</h2>
            <p>StreetCoins are internal platform utility tokens used strictly to facilitate software interactions, peer-to-peer appreciation, and escrow routing within the network ecosystem.</p>
            <ul>
                <li><strong>Not Securities or Currency:</strong> StreetCoins are non-interest-bearing platform credits. They do not represent equity, debt, securities, or legal tender in any jurisdiction.</li>
                <li><strong>Deposit Processing Fees:</strong> Fiat deposits via third-party payment gateways (Stripe) are subject to a non-refundable network processing fee of 6% + $0.30 USD to cover operational infrastructure and gateway costs.</li>
                <li><strong>Cashout Concierge:</strong> Fiat redemption requests are subject to manual administrative review, anti-fraud verification, and platform solvency checks. The Platform reserves the right to reject cashouts originating from fraudulent or abusive activity.</li>
            </ul>

            <h2>4. Black Market & Smart Escrow Software</h2>
            <p>The Black Market and Smart Escrow engines are automated software tools provided "AS IS" to facilitate peer-to-peer commerce.</p>
            <ul>
                <li><strong>Neutral Facilitator:</strong> The Platform acts solely as a neutral software venue and escrow holder. The Platform does not inspect, guarantee, warrant, or verify the quality, safety, legality, or delivery of goods, intel, or services listed on the market.</li>
                <li><strong>Escrow Deductions:</strong> Escrow disbursals algorithmically deduct a 5% platform treasury fee upon successful release of funds.</li>
                <li><strong>Dispute Resolution:</strong> Buyers and sellers engage in trades at their own risk. Escrow funds held in active status will automatically refund to the sender after 24 hours if unreleased, unless administratively intervened.</li>
            </ul>

            <h2>5. Acceptable Use Policy (AUP)</h2>
            <p>While private E2EE channels are mathematically unmoderated by design, the public areas of the Platform (Global Feed, User Profiles, Public Market Listings) are strictly governed by this AUP. Users are prohibited from utilizing public features for distribution of CSAM, threats of physical violence, unannounced malware, or denial-of-service attacks.</p>

            <h2>6. Limitation of Liability</h2>
            <p>To the maximum extent permitted by law, Street Code 101, its operators, and developers shall not be liable for any direct, indirect, incidental, or consequential damages resulting from platform downtime, lost cryptographic keys, unreleased escrow funds, or illegal user conduct.</p>

            <a href="/dashboard" class="back-btn">Return to Terminal</a>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/invite/generate', methods=['POST'])
@limiter.limit("10 per hour")
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

                conn.commit()
                print(f"[*] Genesis Account created for {username} via $20 Paywall.")

            elif purpose == 'pro_upgrade':
                username = metadata.get('username') or session_obj.get('client_reference_id')
                if username:
                    cur.execute("UPDATE users SET is_pro = TRUE WHERE username = %s", (username,))
                    conn.commit()
                    print(f"[*] Operator {username} upgraded to Pro Status.")

            elif purpose == 'fiat_coin_purchase':
                username = metadata.get('username')
                usd_amount = float(metadata.get('usd_amount', 10.0))
                
                # Base conversion: $1 USD = 100 StreetCoins
                amount_total_cents = int(usd_amount * 100)
                
                # --- UPDATED SOLVENCY ALGORITHM ---
                total_deduction = int(amount_total_cents * 0.06) + 30
                net_coins = amount_total_cents - total_deduction
                
                if net_coins < 0:
                    net_coins = 0
                
                try:
                    admin_user = os.getenv('ADMIN_USERNAME', 'catch_flight')
                    
                    # Deduct from Central Bank
                    cur.execute("UPDATE users SET wallet_balance = wallet_balance - %s WHERE username = %s", (net_coins, admin_user))
                    
                    # Add to User
                    cur.execute("UPDATE users SET wallet_balance = COALESCE(wallet_balance, 0) + %s WHERE username = %s", (net_coins, username))
                    
                    # Immutable Ledger Logs
                    cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'deposit', %s)", (username, net_coins, f"Stripe Deposit (${usd_amount:.2f} USD)"))
                    cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'transfer_out', %s)", (admin_user, -net_coins, f"Central Bank Fiat Mint to @{username}"))
                    
                    conn.commit()
                    print(f"[*] Routed {net_coins} Net StreetCoins from Central Bank to @{username} (${usd_amount} USD deposit).")
                except Exception as e:
                    print(f"[-] StreetCoin routing webhook error: {e}")

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
        
        cur.execute("SELECT vote_value FROM street_cred_votes WHERE voter = %s AND target_username = %s", (session['username'], username))
        vote_row = cur.fetchone()
        my_vote = vote_row[0] if vote_row else 0
        
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
            'street_cred': cred,
            'my_vote': my_vote
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
        
    cur.execute("SELECT vote_value FROM street_cred_votes WHERE voter = %s AND target_username = %s", (voter, username))
    existing_vote = cur.fetchone()
    
    if existing_vote and existing_vote[0] == vote_val:
        # User clicked the same vote again; toggle it off
        cur.execute("DELETE FROM street_cred_votes WHERE voter = %s AND target_username = %s", (voter, username))
    else:
        # Insert new or overwrite existing
        cur.execute("""
            INSERT INTO street_cred_votes (voter, target_username, vote_value)
            VALUES (%s, %s, %s)
            ON CONFLICT (voter, target_username) 
            DO UPDATE SET vote_value = EXCLUDED.vote_value, timestamp = CURRENT_TIMESTAMP
        """, (voter, username, vote_val))
        
        # Notify the target user of the new vote
        action = "vouched for" if vote_val == 1 else "burned"
        msg = f"An anonymous operator {action} your Street Cred."
        cur.execute("INSERT INTO notifications (username, type, message) VALUES (%s, 'vote', %s)", (username, msg))
    
    conn.commit()
    cred = calculate_street_cred(username, conn)
    conn.close()
    
    return jsonify({'status': 'success', 'street_cred': cred})

@app.route('/api/upload', methods=['POST'])
@limiter.limit("20 per minute")
def api_upload():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    if 'photo' not in request.files: return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['photo']
    if file.filename == '': return jsonify({'error': 'No file selected'}), 400

    # MAGIC BYTE VALIDATION: Inspect actual file contents, not just the extension
    file_header = file.read(2048)
    kind = filetype.guess(file_header)
    if kind is None or not kind.mime.startswith('image/'):
        return jsonify({'error': 'Sanitization failed: Invalid or executable file type detected.'}), 400
    
    # Reset file pointer after reading headers
    file.seek(0)

    try:
        ext = kind.extension if kind else 'png'
        filename = f"{uuid.uuid4().hex}_{session['username']}.{ext}"
        
        s3_client.upload_fileobj(
            file,
            BUCKET_NAME,
            filename,
            ExtraArgs={'ContentType': kind.mime if kind else 'image/png'}
        )
        
        raw_endpoint = os.getenv('AWS_ENDPOINT_URL', '').rstrip('/')
        # Force the frontend URL to HTTP if we are running locally
        endpoint = raw_endpoint.replace('https://', 'http://') if '127.0.0.1' in raw_endpoint else raw_endpoint
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
    
    if action in ['like', 'dislike']:
        is_dislike = (action == 'dislike')
        cur.execute("SELECT is_dislike FROM post_likes WHERE post_id = %s AND username = %s", (post_id, session['username']))
        existing = cur.fetchone()
        
        cur.execute("DELETE FROM post_likes WHERE post_id = %s AND username = %s", (post_id, session['username']))
        
        if not existing or existing[0] != is_dislike:
            cur.execute("INSERT INTO post_likes (post_id, username, is_dislike) VALUES (%s, %s, %s)", (post_id, session['username'], is_dislike))
    elif action == 'comment':
        cur.execute("INSERT INTO post_comments (post_id, username, content) VALUES (%s, %s, %s)", (post_id, session['username'], request.json.get('content')))
    elif action == 'share':
        cur.execute("SELECT content, image_url FROM posts WHERE id = %s", (post_id,))
        og_post = cur.fetchone()
        if og_post:
            new_content = f"{request.json.get('caption', '')}\n\n[Shared]: {og_post[0]}"
            cur.execute("INSERT INTO posts (username, content, image_url, is_wall_post, target_username) VALUES (%s, %s, %s, TRUE, %s)", 
                        (session['username'], new_content, og_post[1], session['username']))
    
    cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = FALSE", (post_id,))
    likes = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = TRUE", (post_id,))
    dislikes = cur.fetchone()[0]
    
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'likes': likes, 'dislikes': dislikes})

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
    
    try:
        amount_coins = int(request.json.get('amount', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount.'}), 400
        
    if amount_coins <= 0:
        return jsonify({'error': 'Amount must be greater than zero.'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT wallet_balance FROM users WHERE username = %s", (session['username'],))
        row = cur.fetchone()
        balance = row[0] if row and row[0] else 0
        
        if balance < amount_coins:
            conn.close()
            return jsonify({'error': 'Insufficient StreetCoins.'}), 400
            
        cur.execute("UPDATE users SET wallet_balance = wallet_balance - %s WHERE username = %s", (amount_coins, session['username']))
        # We'll reuse amount_cents column to hold the coin amount for now
        cur.execute("INSERT INTO pool_contributions (pool_id, username, amount_cents) VALUES (%s, %s, %s)", (pool_id, session['username'], amount_coins))
        cur.execute("UPDATE money_pools SET total_escrow_cents = total_escrow_cents + %s WHERE id = %s", (amount_coins, pool_id))
        
        # Write the deduction to the immutable ledger
        cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'transfer_out', %s)", 
                    (session['username'], -amount_coins, f"Deposited into Group Pool #{pool_id}"))
        
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/pools/<int:pool_id>/release', methods=['POST'])
def release_pool(pool_id):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    receiver = request.json.get('receiver')
    if not receiver:
        return jsonify({'error': 'Missing receiver'}), 400
        
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT creator, status, total_escrow_cents FROM money_pools WHERE id = %s", (pool_id,))
        pool = cur.fetchone()
        
        if not pool or pool[0] != session['username'] or pool[1] != 'active':
            conn.close()
            return jsonify({'error': 'Only creator can release active pools'}), 403

        amount_coins = pool[2]
        
        cur.execute("UPDATE money_pools SET status = 'released', released_to = %s WHERE id = %s", (receiver, pool_id))
        cur.execute("UPDATE users SET wallet_balance = COALESCE(wallet_balance, 0) + %s WHERE username = %s", (amount_coins, receiver))
        
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


# --- FINANCIALS: 1-ON-1 ESCROW & STRIPE ---
@app.route('/api/escrow/create', methods=['POST'])
def create_escrow():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    
    try:
        amount_coins = int(data['amount'])
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount format'}), 400

    if amount_coins <= 0:
        return jsonify({'error': 'Amount must be strictly greater than zero.'}), 400
        
    receiver = data['receiver']
    sender = session['username']
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT wallet_balance FROM users WHERE username = %s", (sender,))
        sender_row = cur.fetchone()
        sender_balance = sender_row[0] if sender_row and sender_row[0] else 0
        
        if sender_balance < amount_coins:
            return jsonify({'error': 'Insufficient StreetCoins in Vault.'}), 400
            
        cur.execute("UPDATE users SET wallet_balance = wallet_balance - %s WHERE username = %s", (amount_coins, sender))
        
        cur.execute("INSERT INTO escrow_transactions (sender, receiver, amount_cents, status) VALUES (%s, %s, %s, 'held_in_escrow') RETURNING id", 
                    (sender, receiver, amount_coins))
        tx_id = cur.fetchone()[0]

        # Write the deduction to the immutable ledger
        cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'transfer_out', %s)", 
                    (sender, -amount_coins, f"Locked in Escrow for @{receiver}"))

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
    
    try:
        cur.execute("SELECT sender, receiver, amount_cents, status FROM escrow_transactions WHERE id = %s", (tx_id,))
        tx = cur.fetchone()
        
        if not tx:
            return jsonify({'error': 'Escrow transaction not found'}), 404
            
        sender, receiver, amount_coins, status = tx[0], tx[1], tx[2], tx[3]
        
        if sender != session['username']:
            cur.execute("SELECT is_admin FROM users WHERE username = %s", (session['username'],))
            admin_row = cur.fetchone()
            if not admin_row or not admin_row[0]:
                return jsonify({'error': 'Only the escrow sender can release funds.'}), 403
                
        if status != 'held_in_escrow':
            return jsonify({'error': f'Escrow cannot be released. Status is {status}.'}), 400

        fee_coins = int(amount_coins * 0.05)
        payout_coins = amount_coins - fee_coins

        cur.execute("UPDATE users SET wallet_balance = COALESCE(wallet_balance, 0) + %s WHERE username = %s", (payout_coins, receiver))
        cur.execute("UPDATE escrow_transactions SET status = 'released_to_receiver' WHERE id = %s", (tx_id,))
        cur.execute("INSERT INTO platform_treasury (source_escrow_id, amount_collected) VALUES (%s, %s)", (tx_id, fee_coins))
        conn.commit()
        
        return jsonify({
            'status': 'success', 
            'message': f'Escrow released. {payout_coins} Coins sent to @{receiver}. Fee: {fee_coins} Coins.'
        })
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': f'Escrow release engine fault: {str(e)}'}), 500
    finally:
        conn.close()


@app.route('/api/wallet/buy-coins', methods=['POST'])
def buy_coins_checkout():
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
                        'name': f'StreetCoins Deposit (${usd_amount:.2f} USD)',
                        'description': f'Native virtual currency funding for @{session["username"]}'
                    },
                    'unit_amount': int(usd_amount * 100),
                },
                'quantity': 1,
            }],
            mode='payment',
            client_reference_id=session['username'],
            metadata={
                'purpose': 'fiat_coin_purchase',
                'username': session['username'],
                'usd_amount': str(usd_amount)
            },
            success_url=request.host_url + 'dashboard?deposit=success',
            cancel_url=request.host_url + 'dashboard?deposit=cancelled'
        )
        return jsonify({'checkout_url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- FINANCIALS: NATIVE VIRTUAL CURRENCY (STREETCOINS) ---

@app.route('/api/wallet/balance')
def api_wallet_balance():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT wallet_balance FROM users WHERE username = %s", (session['username'],))
        row = cur.fetchone()
        balance = row[0] if row and row[0] else 0
    except Exception:
        balance = 0
        
    conn.close()
    return jsonify({'balance_coins': balance})

@app.route('/api/wallet/transfer', methods=['POST'])
def api_wallet_transfer():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    target_username = data.get('target_username')
    
    try:
        amount = int(data.get('amount_coins', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount format'}), 400

    if not target_username or amount <= 0:
        return jsonify({'error': 'Invalid amount or missing parameters'}), 400

    sender = session['username']
    
    if sender == target_username:
        return jsonify({'error': 'Cannot transfer to yourself.'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT wallet_balance FROM users WHERE username = %s", (sender,))
        sender_row = cur.fetchone()
        sender_balance = sender_row[0] if sender_row and sender_row[0] else 0
        
        if sender_balance < amount:
            conn.close()
            return jsonify({'error': 'Insufficient funds.'}), 400

        # Deduct from sender
        cur.execute("UPDATE users SET wallet_balance = wallet_balance - %s WHERE username = %s", (amount, sender))
        # Add to receiver
        cur.execute("UPDATE users SET wallet_balance = COALESCE(wallet_balance, 0) + %s WHERE username = %s", (amount, target_username))
        
        # Notify the receiver
        msg = f"@{sender} routed {amount} Coins to your vault."
        cur.execute("INSERT INTO notifications (username, type, message) VALUES (%s, 'transfer', %s)", (target_username, msg))
        
        # Write to immutable ledger
        cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'transfer_out', %s)", (sender, -amount, f"Sent to @{target_username}"))
        cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'transfer_in', %s)", (target_username, amount, f"Received from @{sender}"))
        
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Capital routed successfully.'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': 'Transfer failed: ' + str(e)}), 500
    finally:
        conn.close()

@app.route('/api/wallet/cashout', methods=['POST'])
def api_wallet_cashout():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    try:
        amount = int(data.get('amount_coins', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount.'}), 400

    payout_method = data.get('payout_method')
    payout_address = data.get('payout_address')

    if amount < 1000: # Minimum $10.00 cashout
        return jsonify({'error': 'Minimum cashout is 1,000 Coins ($10.00 USD).'}), 400
    if not payout_method or not payout_address:
        return jsonify({'error': 'Missing payment destination info.'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT wallet_balance FROM users WHERE username = %s", (session['username'],))
        row = cur.fetchone()
        balance = row[0] if row and row[0] else 0

        if balance < amount:
            return jsonify({'error': 'Insufficient StreetCoins.'}), 400

        # Deduct coins from user
        cur.execute("UPDATE users SET wallet_balance = wallet_balance - %s WHERE username = %s", (amount, session['username']))
        # Log request for Master Admin
        cur.execute("INSERT INTO cashout_requests (username, amount_coins, payout_method, payout_address) VALUES (%s, %s, %s, %s)", 
                    (session['username'], amount, payout_method, payout_address))
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/admin/cashouts', methods=['GET', 'POST'])
def admin_cashouts():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT is_admin FROM users WHERE username = %s", (session['username'],))
    is_admin = cur.fetchone()[0]
    if not is_admin:
        conn.close()
        return jsonify({'error': 'Forbidden: Master Admin clearance required.'}), 403

    if request.method == 'POST':
        req_id = request.json.get('id')
        cur.execute("UPDATE cashout_requests SET status = 'paid' WHERE id = %s", (req_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

    cur.execute("SELECT id, username, amount_coins, payout_method, payout_address, status, created_at FROM cashout_requests ORDER BY id DESC")
    requests_list = [{'id': r[0], 'username': r[1], 'amount_coins': r[2], 'payout_method': r[3], 'payout_address': r[4], 'status': r[5], 'created_at': r[6]} for r in cur.fetchall()]
    conn.close()
    return jsonify(requests_list)

# --- BLACK MARKET COMMERCE ---

@app.route('/api/market/list', methods=['POST'])
def create_market_item():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    title = data.get('title')
    desc = data.get('description')
    price = data.get('price_coins')
    img = data.get('image_url', '')
    
    try:
        price = int(price)
        if price <= 0: raise ValueError
    except:
        return jsonify({'error': 'Invalid price'}), 400
        
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO market_items (seller, title, description, price_coins, image_url) VALUES (%s, %s, %s, %s, %s)",
                (session['username'], title, desc, price, img))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/market/active', methods=['GET'])
def get_market_items():
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, seller, title, description, price_coins, image_url, created_at FROM market_items WHERE status = 'active' ORDER BY id DESC")
    items = [{'id': r[0], 'seller': r[1], 'title': r[2], 'description': r[3], 'price_coins': r[4], 'image_url': r[5]} for r in cur.fetchall()]
    conn.close()
    return jsonify(items)

@app.route('/api/profile/<username>/market', methods=['GET'])
def get_user_market_items(username):
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, seller, title, description, price_coins, image_url, created_at FROM market_items WHERE seller = %s AND status = 'active' ORDER BY id DESC", (username,))
    items = [{'id': r[0], 'seller': r[1], 'title': r[2], 'description': r[3], 'price_coins': r[4], 'image_url': r[5]} for r in cur.fetchall()]
    conn.close()
    return jsonify(items)

@app.route('/api/market/buy/<int:item_id>', methods=['POST'])
def buy_market_item(item_id):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    buyer = session['username']
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Check item status and get price/seller
        cur.execute("SELECT seller, price_coins, title, status FROM market_items WHERE id = %s", (item_id,))
        item = cur.fetchone()
        if not item or item[3] != 'active':
            return jsonify({'error': 'Item unavailable or already sold.'}), 400
            
        seller, price_coins, title = item[0], item[1], item[2]
        
        if seller == buyer:
            return jsonify({'error': 'Cannot purchase your own listing.'}), 400
            
        # Check balance
        cur.execute("SELECT wallet_balance FROM users WHERE username = %s", (buyer,))
        bal_row = cur.fetchone()
        balance = bal_row[0] if bal_row and bal_row[0] else 0
        
        if balance < price_coins:
            return jsonify({'error': 'Insufficient StreetCoins.'}), 400
            
        # Deduct from buyer
        cur.execute("UPDATE users SET wallet_balance = wallet_balance - %s WHERE username = %s", (price_coins, buyer))
        
        # Create Escrow Transaction locking the funds
        cur.execute("INSERT INTO escrow_transactions (sender, receiver, amount_cents, status) VALUES (%s, %s, %s, 'held_in_escrow') RETURNING id", 
                    (buyer, seller, price_coins))
        tx_id = cur.fetchone()[0]
        
        # Update Item Status
        cur.execute("UPDATE market_items SET status = 'sold' WHERE id = %s", (item_id,))
        
        # Log Immutable Transaction
        cur.execute("INSERT INTO wallet_transactions (username, amount, tx_type, description) VALUES (%s, %s, 'transfer_out', %s)", (buyer, -price_coins, f"Escrow: Bought '{title}'"))
        
        # Notify Seller
        msg = f"@{buyer} purchased '{title}'. {price_coins} Coins are locked in Escrow pending your delivery."
        cur.execute("INSERT INTO notifications (username, type, message) VALUES (%s, 'market', %s)", (seller, msg))
        
        conn.commit()
        return jsonify({'status': 'success', 'escrow_id': tx_id})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# --- SUPPORT DESK ---

@app.route('/api/support/contact', methods=['POST'])
@limiter.limit("3 per hour")
def contact_support():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    user_email = data.get('email', '')
    message = data.get('message', '')
    
    if not message or not user_email:
        return jsonify({'error': 'Email and message are required.'}), 400
        
    subject = f"Support Ticket from @{session['username']}"
    body_html = f"""
    <h3>New Support Request</h3>
    <p><strong>Operator:</strong> @{session['username']}</p>
    <p><strong>Reply-To:</strong> {user_email}</p>
    <hr>
    <p><strong>Concern / Intel:</strong></p>
    <p style="white-space: pre-wrap;">{message}</p>
    """
    
    # Trigger the SMTP engine to send the email to the admin
    success = send_system_email('admin@streetcode101.com', subject, body_html)
    
    if success:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'error': 'Failed to route transmission. SMTP engine offline.'}), 500
# --- NOTIFICATION CENTER (THE PAGER) ---

@app.route('/api/notifications')
def get_notifications():
    if 'username' not in session: return jsonify([])
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, type, message, is_read, created_at FROM notifications WHERE username = %s ORDER BY id DESC LIMIT 30", (session['username'],))
    notifs = [{'id': r[0], 'type': r[1], 'message': r[2], 'is_read': r[3]} for r in cur.fetchall()]
    conn.close()
    return jsonify(notifs)

@app.route('/api/notifications/read', methods=['POST'])
def read_notifications():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE notifications SET is_read = TRUE WHERE username = %s AND is_read = FALSE", (session['username'],))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/wallet/history')
def api_wallet_history():
    if 'username' not in session: return jsonify([])
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Check if the requester has Master Admin clearance
    cur.execute("SELECT is_admin FROM users WHERE username = %s", (session['username'],))
    admin_row = cur.fetchone()
    is_admin = admin_row[0] if admin_row else False
    
    if is_admin:
        # Master Admin overrides user filters and sees ALL network transactions
        cur.execute("SELECT username, amount, tx_type, description, created_at FROM wallet_transactions ORDER BY id DESC LIMIT 200")
        # Prefix the description with the operator's handle for global visibility
        history = [{'amount': r[1], 'type': r[2], 'description': f"[@{r[0]}] {r[3]}", 'date': r[4].isoformat()} for r in cur.fetchall()]
    else:
        # Standard Operator view
        cur.execute("SELECT amount, tx_type, description, created_at FROM wallet_transactions WHERE username = %s ORDER BY id DESC LIMIT 50", (session['username'],))
        history = [{'amount': r[0], 'type': r[1], 'description': r[2], 'date': r[3].isoformat()} for r in cur.fetchall()]
        
    conn.close()
    return jsonify(history)
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
