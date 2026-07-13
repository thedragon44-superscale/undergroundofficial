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
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-secret-fallback")
CORS(app)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

connected_clients = {}

def get_db_connection():
    return psycopg2.connect(os.getenv("NEON_DATABASE_URL"))

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 1. Users Table
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
            stripe_account TEXT
        )
    ''')
    
    # 2. Invite Keys Table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS invite_keys (
            id SERIAL PRIMARY KEY,
            key VARCHAR(50) UNIQUE NOT NULL,
            creator VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'active',
            used_by VARCHAR(50)
        )
    ''')

    # 3. Direct Messages Table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender VARCHAR(50) NOT NULL,
            receiver VARCHAR(50) NOT NULL,
            text TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 4. Social Posts Table (Feed & Wall)
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

    # 5. Post Interactions
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

    # 6. Group Workspaces
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

    # 7. Financial Escrow & Pools
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

    conn.commit()
    conn.close()

# --- AUTHENTICATION & ACCESS CONTROL ---

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
        cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid clearance credentials.', 'error')
            
    return render_template('login.html', title='Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        invite_key = request.form['invite_key']
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verify Invite
        cur.execute("SELECT id FROM invite_keys WHERE key = %s AND status = 'active'", (invite_key,))
        invite = cur.fetchone()
        
        if not invite:
            flash('Invalid or expired Invite Key.', 'error')
            conn.close()
            return redirect(url_for('register'))
            
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        try:
            # 1. Create User
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed))
            
            # 2. Consume Invite
            cur.execute("UPDATE invite_keys SET status = 'used', used_by = %s WHERE id = %s", (username, invite[0]))
            
            # 3. Create Default Invite Key for New User
            new_key = "METRO-" + str(uuid.uuid4())[:8].upper()
            cur.execute("INSERT INTO invite_keys (key, creator) VALUES (%s, %s)", (new_key, username))
            
            # 4. Create Lightning Wallet
            headers = {"X-Api-Key": os.getenv("LNBITS_MASTER_KEY"), "Content-Type": "application/json"}
            payload = {"name": f"Vault_{username}"}
            res = requests.post(f"{os.getenv('LNBITS_URL')}/api/v1/account", json=payload, headers=headers)
            
            if res.status_code == 201:
                wallet_data = res.json()
                cur.execute("UPDATE users SET ln_wallet_id = %s, ln_admin_key = %s WHERE username = %s", 
                           (wallet_data.get('wallets')[0]['id'], wallet_data.get('wallets')[0]['adminkey'], username))
            
            conn.commit()
            session['username'] = username
            session['is_first_login'] = True
            return redirect(url_for('dashboard'))
            
        except psycopg2.IntegrityError:
            conn.rollback()
            flash('Operator handle already exists.', 'error')
        finally:
            conn.close()
            
    return render_template('login.html', title='Register')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/invite/generate', methods=['POST'])
def generate_invite():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    new_key = "METRO-" + str(uuid.uuid4())[:8].upper()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO invite_keys (key, creator) VALUES (%s, %s)", (new_key, session['username']))
    conn.commit()
    conn.close()
    return jsonify({'key': new_key})

@app.route('/api/invites/ledger')
def get_invite_ledger():
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT key, status, used_by FROM invite_keys WHERE creator = %s ORDER BY id DESC", (session['username'],))
    ledgers = [{'key': r[0], 'status': r[1], 'used_by': r[2]} for r in cur.fetchall()]
    conn.close()
    return jsonify(ledgers)

@app.route('/api/users')
def api_users():
    if 'username' not in session: return jsonify([]), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, profile_pic FROM users")
    users = [{'username': r[0], 'profile_pic': r[1]} for r in cur.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session: return redirect(url_for('login'))
    show_welcome = session.pop('is_first_login', False)
    return render_template('dashboard.html', username=session['username'], show_welcome=show_welcome)
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


# --- USER PROFILE & MEDIA UPLOADS ---

@app.route('/api/profile/<username>', methods=['GET', 'POST'])
def api_profile(username):
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    
    if request.method == 'POST':
        if session['username'] != username: return jsonify({'error': 'Unauthorized'}), 403
        data = request.json
        if 'bio' in data: cur.execute("UPDATE users SET bio = %s WHERE username = %s", (data['bio'], username))
        if 'profile_pic' in data: cur.execute("UPDATE users SET profile_pic = %s WHERE username = %s", (data['profile_pic'], username))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

    # GET Profile (Now checks Invite Ledger for Parent Node)
    cur.execute("""
        SELECT u.username, u.bio, u.profile_pic, u.ln_wallet_id, u.stripe_account, i.creator
        FROM users u
        LEFT JOIN invite_keys i ON i.used_by = u.username
        WHERE u.username = %s
    """, (username,))
    user = cur.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'username': user[0], 
            'bio': user[1] or "", 
            'profile_pic': user[2] or "",
            'ln_wallet_id': user[3],
            'stripe_account': user[4],
            'invited_by': user[5]
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    if 'photo' not in request.files: return jsonify({'error': 'No file part'}), 400
    file = request.files['photo']
    if file.filename == '': return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = secure_filename(str(uuid.uuid4()) + "_" + file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'url': '/static/uploads/' + filename})


# --- SOCIAL FEED & WALL ---

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

    cur.execute("SELECT p.id, p.username, p.content, p.image_url, u.profile_pic FROM posts p JOIN users u ON p.username = u.username WHERE p.is_wall_post = FALSE ORDER BY p.id DESC LIMIT 50")
    posts = []
    for row in cur.fetchall():
        post_id = row[0]
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = FALSE", (post_id,))
        likes = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s AND is_dislike = TRUE", (post_id,))
        dislikes = cur.fetchone()[0]
        cur.execute("SELECT username, content FROM post_comments WHERE post_id = %s ORDER BY id ASC", (post_id,))
        comments = cur.fetchall()
        posts.append({'id': post_id, 'username': row[1], 'content': row[2], 'image_url': row[3], 'profile_pic': row[4], 'likes_count': likes, 'dislikes_count': dislikes, 'comments': comments})
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
    amount_cents = int(float(data['amount']) * 100)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO escrow_transactions (sender, receiver, amount_cents) VALUES (%s, %s, %s) RETURNING id", 
                (session['username'], data['receiver'], amount_cents))
    tx_id = cur.fetchone()[0]
    conn.commit()
    conn.close()
    return jsonify({'id': tx_id})

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

@app.route('/api/escrow/release', methods=['POST'])
def release_escrow():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    tx_id = request.json.get('id')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT sender, status FROM escrow_transactions WHERE id = %s", (tx_id,))
    tx = cur.fetchone()
    if tx and tx[0] == session['username'] and tx[1] == 'held_in_escrow':
        cur.execute("UPDATE escrow_transactions SET status = 'released_to_receiver' WHERE id = %s", (tx_id,))
        conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

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
        amount_cents = int(float(data['amount']) * 100)
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price_data': {'currency': 'usd', 'product_data': {'name': f'Escrow Funding TX-{data["id"]}'}, 'unit_amount': amount_cents}, 'quantity': 1}],
            mode='payment',
            success_url=request.host_url + 'dashboard',
            cancel_url=request.host_url + 'dashboard'
        )
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# --- FINANCIALS: LIGHTNING CRYPTO VAULT & DIRECT TRANSFERS ---

@app.route('/api/wallet/balance')
def api_wallet_balance():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ln_wallet_id FROM users WHERE username = %s", (session['username'],))
    wallet_id = cur.fetchone()
    conn.close()
    
    if not wallet_id or not wallet_id[0]: return jsonify({'status': 'mock_vault_active'})
    
    headers = {"X-Api-Key": wallet_id[0]}
    res = requests.get(f"{os.getenv('LNBITS_URL')}/api/v1/wallet", headers=headers)
    if res.status_code == 200:
        return jsonify({'balance_sats': res.json().get('balance', 0) // 1000})
    return jsonify({'error': 'Failed to fetch balance'}), 500

@app.route('/api/wallet/invoice', methods=['POST'])
def api_wallet_invoice():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    amount_sats = request.json.get('amount_sats')
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ln_wallet_id FROM users WHERE username = %s", (session['username'],))
    wallet_id = cur.fetchone()[0]
    conn.close()
    
    headers = {"X-Api-Key": wallet_id, "Content-Type": "application/json"}
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
    cur.execute("SELECT ln_wallet_id FROM users WHERE username = %s", (session['username'],))
    wallet_id = cur.fetchone()[0]
    conn.close()
    
    headers = {"X-Api-Key": wallet_id, "Content-Type": "application/json"}
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
    cur.execute("SELECT ln_wallet_id FROM users WHERE username = %s", (session['username'],))
    sender_wallet = cur.fetchone()[0]
    cur.execute("SELECT ln_wallet_id FROM users WHERE username = %s", (target_username,))
    target_wallet_row = cur.fetchone()
    conn.close()

    if not target_wallet_row or not target_wallet_row[0]:
        return jsonify({'error': 'Target operator does not have an active financial vault.'}), 400
    target_wallet = target_wallet_row[0]

    # 1. Generate Invoice on Target's Wallet
    headers_target = {"X-Api-Key": target_wallet, "Content-Type": "application/json"}
    payload_target = {"out": False, "amount": amount_sats, "memo": f"Direct Transfer from {session['username']}"}
    inv_res = requests.post(f"{os.getenv('LNBITS_URL')}/api/v1/payments", json=payload_target, headers=headers_target)
    
    if inv_res.status_code != 201:
        return jsonify({'error': 'Failed to route destination invoice.'}), 500
    bolt11 = inv_res.json().get('payment_request')

    # 2. Pay Invoice from Sender's Wallet
    headers_sender = {"X-Api-Key": sender_wallet, "Content-Type": "application/json"}
    payload_sender = {"out": True, "bolt11": bolt11}
    pay_res = requests.post(f"{os.getenv('LNBITS_URL')}/api/v1/payments", json=payload_sender, headers=headers_sender)

    if pay_res.status_code == 201:
        return jsonify({'status': 'success', 'message': 'Capital routed successfully.'})
    else:
        return jsonify({'error': 'Insufficient funds or routing failure.'}), 400


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

async def ws_handler(websocket):
    username = None
    try:
        async for message in websocket:
            data = json.loads(message)
            
            # Initial Connection Handshake
            if "username" in data and len(data) == 1:
                username = data["username"]
                connected_clients[username] = websocket
                await broadcast_presence()
                
                # Retrieve encrypted 1-on-1 history
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT sender, receiver, text FROM messages WHERE sender = %s OR receiver = %s ORDER BY id ASC", (username, username))
                history = [{"sender": r[0], "receiver": r[1], "text": r[2]} for r in cur.fetchall()]
                conn.close()
                await websocket.send(json.dumps({"is_history": True, "history": history}))
                continue

            # Handle Group Chat Messages
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

            # Handle 1-on-1 Typing Indicators
            if data.get("is_typing"):
                receiver = data.get("receiver")
                if receiver in connected_clients:
                    await connected_clients[receiver].send(json.dumps({"is_typing": True, "sender": username}))
                continue

            # Handle 1-on-1 Messages
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
