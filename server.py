from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt 
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity 
from flask_cors import CORS
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson import ObjectId 
from pyparsing import wraps
from datetime import timedelta, datetime
from base64 import b64decode
from dotenv import load_dotenv
from google.oauth2 import id_token as google_id_token 
from google.auth.transport import requests as google_requests
import os, re, secrets, string

# Load env
load_dotenv()
app = Flask(__name__)
CORS(app)

# Konfigurasi App
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'kankerganas')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
app.config['API_KEY'] = os.getenv('API_KEY', 'secretmykey')
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Konfigurasi Email
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=('Aplikasi Kanker', os.getenv('MAIL_USERNAME'))
)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)

# Database Mongo
client = MongoClient(os.getenv('MONGODB_URI'))
print(os.getenv('MONGODB_URI'))  # Tambahkan sementara di server.py untuk cekpip install dnspython

db = client['capstonesmt6']
users = db['capstone']
sadari_col = db['sadari_history']
accounting_col = db['accounting_logs']
pose_history_col = db['pose_history']
assesmen_col = db['assesmen_history']




# Artikel DB
article_client = MongoClient(os.getenv('ARTICLE_MONGO_URI'))
article_db = article_client[os.getenv('ARTICLE_DB_NAME', 'artikel_db')]
articles = article_db[os.getenv('ARTICLE_COLL_NAME', 'artikel')]

# Helpers
def is_valid_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email or '') is not None

def random_password(n=12):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))

def generate_otp():
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def require_api_key(func):
    @wraps(func)
    def wrap(*a, **k):
        if request.headers.get('x-api-key') != app.config['API_KEY']:
            return jsonify({"message": "Unauthorized"}), 401
        return func(*a, **k)
    return wrap

def log_activity(user_id, action, detail=''):
    accounting_col.insert_one({
        'user_id': ObjectId(user_id),
        'action': action,
        'detail': detail,
        'timestamp': datetime.utcnow()
    })

# ======================== AUTH ========================
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name, email, pwd, phone = (data.get(k) for k in ('name','email','password','phone'))
    role = data.get('role', 'General')
    if not all([name, email, pwd, phone]):
        return jsonify({"message": "All fields are required!"}), 400
    if not is_valid_email(email):
        return jsonify({"message": "Invalid email format!"}), 400
    if users.find_one({'email': email}):
        return jsonify({"message": "Email already registered!"}), 400

    hashed = bcrypt.generate_password_hash(pwd).decode('utf-8')
    otp = generate_otp()
    otp_hash = bcrypt.generate_password_hash(otp).decode('utf-8')

    user_id = users.insert_one({
        'name': name, 'email': email,
        'password': hashed, 'phone': phone, 'role': role,
        'profile_picture': '', 'is_verified': False,
        'verify_otp': otp_hash,
        'verify_exp': datetime.utcnow() + timedelta(minutes=10)
    }).inserted_id

    try:
        mail.send(Message(
            subject="OTP Verifikasi Email",
            recipients=[email],
            body=f"OTP Anda: {otp} (berlaku 10 menit)."
        ))
    except Exception as e:
        app.logger.error(f"Email error: {e}")

    return jsonify({"message": "Registered! OTP sent."}), 201

@app.route('/verify_email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email, otp = data.get('email'), data.get('otp')
    user = users.find_one({'email': email})
    if not user or not otp:
        return jsonify({"message": "Invalid email or OTP"}), 400
    if user.get('is_verified'):
        return jsonify({"message": "Already verified"}), 400
    if datetime.utcnow() > user['verify_exp']:
        return jsonify({"message": "OTP expired"}), 400
    if not bcrypt.check_password_hash(user.get('verify_otp', ''), otp):
        return jsonify({"message": "Invalid OTP"}), 400

    users.update_one({'_id': user['_id']}, {
        '$set': {'is_verified': True},
        '$unset': {'verify_otp': "", 'verify_exp': ""}
    })
    log_activity(user['_id'], 'email_verification', 'User verified email')
    token = create_access_token(identity=str(user['_id']))
    return jsonify({
        "message": "Verified!", "access_token": token,
        "name": user['name'], "email": user['email'],
        "phone": user['phone'], "role": user['role'],
        "profile_picture": user.get('profile_picture','')
    }), 200

@app.route('/login', methods=['POST'])
def login():
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Basic '):
        try:
            email, pwd = b64decode(auth.split(' ')[1]).decode().split(':')
        except:
            return jsonify({"message": "Invalid Basic Auth"}), 400
    else:
        data = request.get_json()
        email, pwd = data.get('email'), data.get('password')

    if not email or not pwd:
        return jsonify({"message": "Email and password required"}), 400

    user = users.find_one({'email': email})
    if not user or not bcrypt.check_password_hash(user['password'], pwd):
        return jsonify({"message": "Invalid credentials!"}), 401
    if not user.get('is_verified'):
        return jsonify({"message": "Verify your email"}), 403

    log_activity(user['_id'], 'login', 'Login successful')
    token = create_access_token(identity=str(user['_id']))
    return jsonify({
        "message": "Login success", "access_token": token,
        "name": user['name'], "email": email,
        "phone": user.get('phone', ''), "role": user['role'],
        "profile_picture": user.get('profile_picture', '')
    }), 200

@app.route('/login_google', methods=['POST'])
def login_google():
    id_token_str = request.get_json().get('id_token')
    if not id_token_str or not GOOGLE_CLIENT_ID:
        return jsonify({"message": "id_token/Client ID missing"}), 400
    try:
        idinfo = google_id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), audience=GOOGLE_CLIENT_ID)
    except ValueError:
        return jsonify({"message": "Invalid id_token"}), 401

    email = idinfo['email']
    user = users.find_one({'email': email})
    if not user:
        uid = users.insert_one({
            'name': idinfo.get('name', email),
            'email': email, 'phone': '', 'role': 'General',
            'password': bcrypt.generate_password_hash(random_password()).decode('utf-8'),
            'profile_picture': idinfo.get('picture', ''),
            'is_verified': True
        }).inserted_id
        user = users.find_one({'_id': uid})

    log_activity(user['_id'], 'login_google', 'Google login success')
    token = create_access_token(identity=str(user['_id']))
    return jsonify({
        "message": "Google login success", "access_token": token,
        "name": user['name'], "email": email,
        "phone": user.get('phone', ''), "role": user['role'],
        "profile_picture": user.get('profile_picture', '')
    }), 200

# ======================== RESET PASSWORD ========================
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.get_json().get('email')
    if not email or not is_valid_email(email):
        return jsonify({"message": "Valid email required"}), 400
    user = users.find_one({'email': email})
    if not user:
        return jsonify({"message": "Email not found"}), 404
    if not user.get('is_verified'):
        return jsonify({"message": "Email not verified"}), 403

    otp = generate_otp()
    otp_hash = bcrypt.generate_password_hash(otp).decode('utf-8')
    users.update_one({'email': email}, {
        '$set': {'reset_otp': otp_hash, 'reset_exp': datetime.utcnow() + timedelta(minutes=10)}
    })

    try:
        mail.send(Message("Reset OTP", recipients=[email],
                          body=f"OTP Reset Password: {otp} (10 menit)"))
    except Exception as e:
        app.logger.error(f"Reset OTP email failed: {e}")

    return jsonify({"message": "OTP sent"}), 200

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email, otp, new_pwd = data.get('email'), data.get('otp'), data.get('new_password')
    user = users.find_one({'email': email})
    if not user or not bcrypt.check_password_hash(user.get('reset_otp', ''), otp):
        return jsonify({"message": "Invalid OTP"}), 400
    if datetime.utcnow() > user['reset_exp']:
        return jsonify({"message": "OTP expired"}), 400

    users.update_one({'email': email}, {
        '$set': {'password': bcrypt.generate_password_hash(new_pwd).decode()},
        '$unset': {'reset_otp': "", 'reset_exp': ""}
    })
    log_activity(user['_id'], 'reset_password', 'Password reset via OTP')
    return jsonify({"message": "Password updated"}), 200

# ======================== PROFILE ========================
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    uid = get_jwt_identity()
    user = users.find_one({'_id': ObjectId(uid)})
    if not user:
        return jsonify({"message": "Not found"}), 404
    return jsonify({
        "name": user['name'], "email": user['email'],
        "phone": user.get('phone', ''), "role": user['role'],
        "profile_picture": user.get('profile_picture', '')
    }), 200

@app.route('/update_profile', methods=['PUT'])
@jwt_required()
def update_profile():
    uid = get_jwt_identity()
    data = request.get_json()
    mod = {}
    if 'name' in data:
        mod['name'] = data['name']
        log_activity(uid, 'change_username', f"New name: {data['name']}")
    if 'phone' in data:
        mod['phone'] = data['phone']
    if 'password' in data:
        mod['password'] = bcrypt.generate_password_hash(data['password']).decode()
        log_activity(uid, 'change_password', 'Password updated')
    if 'profile_picture' in data:
        mod['profile_picture'] = data['profile_picture']
    if not mod:
        return jsonify({"message": "No changes"}), 400
    users.update_one({'_id': ObjectId(uid)}, {'$set': mod})
    return jsonify({"message": "Updated"}), 200

@app.route('/delete_account', methods=['DELETE'])
@jwt_required()
def delete_account():
    uid = get_jwt_identity()
    res = users.delete_one({'_id': ObjectId(uid)})
    log_activity(uid, 'delete_account', 'Account deleted')
    return jsonify({"message": "Deleted" if res.deleted_count else "Not found"}), 200

# ======================== SADARI NOTES ========================
@app.route('/sadari/upload', methods=['POST'])
@jwt_required()
def upload_sadari():
    uid = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    note = data.get('note') or request.form.get('note')
    if not note:
        return jsonify({"message": "Note required"}), 400
    sadari_col.insert_one({'user': ObjectId(uid), 'note': note, 'timestamp': datetime.utcnow()})
    log_activity(uid, 'self_check', 'SADARI note uploaded')
    return jsonify({"message": "Uploaded"}), 201

@app.route('/history', methods=['GET'])
@jwt_required()
def get_history():
    uid = get_jwt_identity()
    records = sadari_col.find({'user': ObjectId(uid)}).sort('timestamp', -1)
    return jsonify([{
        "note": r['note'],
        "timestamp": r['timestamp'].isoformat()
    } for r in records]), 200

# ======================== ACCOUNTING ========================
@app.route('/accounting_logs', methods=['GET'])
@jwt_required()
def get_logs():
    uid = get_jwt_identity()
    try:
        user_obj_id = ObjectId(uid)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    logs = accounting_col.find({'user_id': user_obj_id}).sort('timestamp', -1)

    return jsonify([{
        "action": l['action'],
        "detail": l.get('detail', ''),
        "timestamp": l['timestamp'].isoformat()
    } for l in logs]), 200

# ======================== ARTIKEL ========================
@app.route('/artikel', methods=['GET'])
@require_api_key
def get_articles():
    docs = articles.find()
    return jsonify({'data': [dict(
        id=str(a['_id']),
        judul=a.get('judul', ''),
        link=a.get('link', ''),
        tanggal_publish=a.get('tanggal_publish', '').isoformat() if a.get('tanggal_publish') else '',
        ringkasan=a.get('ringkasan', ''),
        isi=a.get('isi', ''),
        sumber=a.get('sumber', ''),
        waktu_scraping=a.get('waktu_scraping', '').isoformat() if a.get('waktu_scraping') else ''
    ) for a in docs]}), 200

# ======================== POSE HISTORY ========================

@app.route('/pose_history', methods=['POST'])
@jwt_required()
def save_pose_history():
    uid = get_jwt_identity()
    data = request.get_json()
    label = data.get('label')
    mode = data.get('mode', 'unknown')  # 'camera' atau 'upload'

    if not label:
        return jsonify({"message": "Label is required"}), 400

    pose_history_col.insert_one({
        'user_id': ObjectId(uid),
        'label': label,
        'mode': mode,
        'timestamp': datetime.utcnow()
    })

    log_activity(uid, 'pose_detection', f'Detected: {label} via {mode}')
    return jsonify({"message": "Pose history saved"}), 201

@app.route('/pose_history', methods=['GET'])
@jwt_required()
def get_pose_history():
    uid = get_jwt_identity()
    records = pose_history_col.find({'user_id': ObjectId(uid)}).sort('timestamp', -1)

    return jsonify([
        {
            'label': r.get('label', ''),
            'mode': r.get('mode', 'unknown'),
            'akurasi': r.get('akurasi'),         # ✅ Nilai bisa None jika belum ada
            'repetisi': r.get('repetisi'),       # ✅ Sama, aman meskipun belum diisi
            'timestamp': r['timestamp'].isoformat()
        } for r in records
    ]), 200

# ======================== ASSESMEN LIMFEDEMA ========================
@app.route('/assesmen', methods=['POST'])
@jwt_required()
def simpan_assesmen():
    uid = get_jwt_identity()
    data = request.get_json()

    if not data:
        return jsonify({"message": "No data provided"}), 400

    required_fields = ['skor', 'rata_rata', 'kategori', 'rekomendasi repitisi']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    assesmen_data = {
        'user_id': ObjectId(uid),
        'skor': data['skor'],  # list of 7 skor
        'rata_rata': data['rata_rata'],
        'kategori': data['kategori'],
        'rekomendasi repitisi': data['rekomendasi repitisi'],
        'timestamp': datetime.utcnow()
    }

    assesmen_col.insert_one(assesmen_data)
    log_activity(uid, 'assesmen', f'Kategori: {data["kategori"]}, Rekomendasi repetisi: {data["rekomendasi repitisi"]}')
    return jsonify({"message": "Assesmen saved"}), 201


# ======================== LOGOUT ========================
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    uid = get_jwt_identity()
    log_activity(uid, 'logout', 'User logged out')
    return jsonify({"message": "Logout successful"}), 200

# ======================== RUN ========================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
