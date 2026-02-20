from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'pychat-super-secret-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///pychat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Railway daje PostgreSQL z URL zaczynającym się od postgres:// — Flask wymaga postgresql://
db_url = app.config['SQLALCHEMY_DATABASE_URI']
if db_url.startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace('postgres://', 'postgresql://', 1)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─── MODELE ───────────────────────────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    avatar_color = db.Column(db.String(7), default='#5865F2')
    status = db.Column(db.String(20), default='online')
    custom_status = db.Column(db.String(100), default='')
    bio = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), default='')
    icon_color = db.Column(db.String(7), default='#5865F2')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    channels = db.relationship('Channel', backref='server', lazy=True, cascade='all, delete-orphan')
    members = db.relationship('ServerMember', backref='server', lazy=True, cascade='all, delete-orphan')

class ServerMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    nickname = db.Column(db.String(80), default='')

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), default='')
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'))
    channel_type = db.Column(db.String(10), default='text')
    position = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='channel', lazy=True, cascade='all, delete-orphan')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime, nullable=True)
    reply_to = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    pinned = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='messages')

class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    emoji = db.Column(db.String(10), nullable=False)

class DirectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.String(200))
    notif_type = db.Column(db.String(30))
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ─── HELPERS ──────────────────────────────────────────────────────────────────

COLORS = ['#5865F2','#57F287','#FEE75C','#EB459E','#ED4245','#3BA55C','#FAA61A','#00B0F4','#9B59B6','#E67E22']

def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization','').replace('Bearer ','')
        if not token:
            return jsonify({'error': 'Brak tokenu'}), 401
        import jwt
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            if not user:
                return jsonify({'error': 'Użytkownik nie istnieje'}), 401
            request.current_user = user
        except:
            return jsonify({'error': 'Nieprawidłowy token'}), 401
        return f(*args, **kwargs)
    return decorated

def make_token(user_id):
    import jwt
    return jwt.encode({'user_id': user_id}, app.config['SECRET_KEY'], algorithm='HS256')

def msg_dict(m):
    return {
        'id': m.id,
        'content': m.content,
        'user_id': m.user_id,
        'username': m.user.username,
        'avatar_color': m.user.avatar_color,
        'channel_id': m.channel_id,
        'created_at': m.created_at.strftime('%H:%M'),
        'date': m.created_at.strftime('%d.%m.%Y'),
        'full_time': m.created_at.strftime('%d.%m.%Y %H:%M'),
        'edited': m.edited,
        'pinned': m.pinned,
        'reply_to': m.reply_to,
    }

# ─── AUTH ─────────────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username','').strip()
    email = data.get('email','').strip()
    password = data.get('password','')
    if not all([username, email, password]):
        return jsonify({'error': 'Wszystkie pola są wymagane'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Nazwa min. 3 znaki'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Hasło min. 6 znaków'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Nazwa użytkownika zajęta'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email już używany'}), 400
    color = COLORS[User.query.count() % len(COLORS)]
    user = User(username=username, email=email, password=generate_password_hash(password), avatar_color=color)
    db.session.add(user)
    db.session.flush()
    # Default server
    server = Server(name=f'Serwer {username}', owner_id=user.id, icon_color=color,
                    description=f'Osobisty serwer użytkownika {username}')
    db.session.add(server)
    db.session.flush()
    db.session.add(ServerMember(server_id=server.id, user_id=user.id, role='owner'))
    db.session.add(Channel(name='ogólny', server_id=server.id, position=0))
    db.session.add(Channel(name='losowy', server_id=server.id, position=1))
    db.session.add(Channel(name='off-topic', server_id=server.id, position=2))
    db.session.commit()
    token = make_token(user.id)
    return jsonify({'token': token, 'user': {'id': user.id, 'username': user.username, 'avatar_color': user.avatar_color}})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email','').strip()
    password = data.get('password','')
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Nieprawidłowy email lub hasło'}), 401
    user.status = 'online'
    db.session.commit()
    token = make_token(user.id)
    return jsonify({'token': token, 'user': {'id': user.id, 'username': user.username, 'avatar_color': user.avatar_color, 'status': user.status}})

@app.route('/api/me')
@token_required
def me():
    u = request.current_user
    return jsonify({'id': u.id, 'username': u.username, 'email': u.email,
                    'avatar_color': u.avatar_color, 'status': u.status,
                    'custom_status': u.custom_status, 'bio': u.bio})

@app.route('/api/me', methods=['PATCH'])
@token_required
def update_me():
    u = request.current_user
    data = request.json
    if 'status' in data: u.status = data['status']
    if 'custom_status' in data: u.custom_status = data['custom_status']
    if 'bio' in data: u.bio = data['bio']
    if 'username' in data:
        new_name = data['username'].strip()
        if new_name and new_name != u.username:
            if User.query.filter_by(username=new_name).first():
                return jsonify({'error': 'Nazwa zajęta'}), 400
            u.username = new_name
    if 'password' in data and data['password']:
        if len(data['password']) < 6:
            return jsonify({'error': 'Hasło min. 6 znaków'}), 400
        u.password = generate_password_hash(data['password'])
    db.session.commit()
    return jsonify({'success': True})

# ─── SERVERS ──────────────────────────────────────────────────────────────────

@app.route('/api/servers')
@token_required
def get_servers():
    u = request.current_user
    memberships = ServerMember.query.filter_by(user_id=u.id).all()
    result = []
    for m in memberships:
        s = m.server
        result.append({'id': s.id, 'name': s.name, 'icon_color': s.icon_color,
                        'description': s.description, 'owner_id': s.owner_id, 'role': m.role})
    return jsonify(result)

@app.route('/api/servers', methods=['POST'])
@token_required
def create_server():
    u = request.current_user
    data = request.json
    name = data.get('name','').strip()
    if not name: return jsonify({'error': 'Nazwa wymagana'}), 400
    color = COLORS[Server.query.count() % len(COLORS)]
    s = Server(name=name, owner_id=u.id, icon_color=color, description=data.get('description',''))
    db.session.add(s)
    db.session.flush()
    db.session.add(ServerMember(server_id=s.id, user_id=u.id, role='owner'))
    db.session.add(Channel(name='ogólny', server_id=s.id, position=0))
    db.session.commit()
    return jsonify({'id': s.id, 'name': s.name, 'icon_color': s.icon_color, 'owner_id': s.owner_id, 'role': 'owner'})

@app.route('/api/servers/<int:sid>', methods=['DELETE'])
@token_required
def delete_server(sid):
    u = request.current_user
    s = Server.query.get_or_404(sid)
    if s.owner_id != u.id: return jsonify({'error': 'Brak uprawnień'}), 403
    db.session.delete(s)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/servers/<int:sid>/join', methods=['POST'])
@token_required
def join_server(sid):
    u = request.current_user
    if ServerMember.query.filter_by(server_id=sid, user_id=u.id).first():
        return jsonify({'error': 'Już jesteś członkiem'}), 400
    db.session.add(ServerMember(server_id=sid, user_id=u.id, role='member'))
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/servers/<int:sid>/leave', methods=['POST'])
@token_required
def leave_server(sid):
    u = request.current_user
    s = Server.query.get_or_404(sid)
    if s.owner_id == u.id: return jsonify({'error': 'Właściciel nie może opuścić serwera'}), 400
    m = ServerMember.query.filter_by(server_id=sid, user_id=u.id).first()
    if m: db.session.delete(m); db.session.commit()
    return jsonify({'success': True})

@app.route('/api/servers/<int:sid>/members')
@token_required
def get_members(sid):
    members = ServerMember.query.filter_by(server_id=sid).all()
    result = []
    for m in members:
        u2 = User.query.get(m.user_id)
        result.append({'id': u2.id, 'username': u2.username, 'avatar_color': u2.avatar_color,
                        'status': u2.status, 'role': m.role, 'custom_status': u2.custom_status})
    return jsonify(result)

@app.route('/api/servers/discover')
@token_required
def discover():
    u = request.current_user
    joined = [m.server_id for m in ServerMember.query.filter_by(user_id=u.id).all()]
    servers = Server.query.filter(~Server.id.in_(joined)).all()
    result = []
    for s in servers:
        count = ServerMember.query.filter_by(server_id=s.id).count()
        result.append({'id': s.id, 'name': s.name, 'icon_color': s.icon_color,
                        'description': s.description, 'members': count})
    return jsonify(result)

# ─── CHANNELS ─────────────────────────────────────────────────────────────────

@app.route('/api/servers/<int:sid>/channels')
@token_required
def get_channels(sid):
    u = request.current_user
    if not ServerMember.query.filter_by(server_id=sid, user_id=u.id).first():
        return jsonify({'error': 'Brak dostępu'}), 403
    channels = Channel.query.filter_by(server_id=sid).order_by(Channel.position).all()
    return jsonify([{'id': c.id, 'name': c.name, 'type': c.channel_type, 'description': c.description} for c in channels])

@app.route('/api/servers/<int:sid>/channels', methods=['POST'])
@token_required
def create_channel(sid):
    u = request.current_user
    m = ServerMember.query.filter_by(server_id=sid, user_id=u.id).first()
    if not m or m.role not in ['owner','admin']: return jsonify({'error': 'Brak uprawnień'}), 403
    data = request.json
    name = data.get('name','').strip().lower().replace(' ','-')
    if not name: return jsonify({'error': 'Nazwa wymagana'}), 400
    pos = Channel.query.filter_by(server_id=sid).count()
    ch = Channel(name=name, server_id=sid, channel_type=data.get('type','text'),
                 description=data.get('description',''), position=pos)
    db.session.add(ch)
    db.session.commit()
    return jsonify({'id': ch.id, 'name': ch.name, 'type': ch.channel_type})

@app.route('/api/channels/<int:cid>', methods=['DELETE'])
@token_required
def delete_channel(cid):
    u = request.current_user
    ch = Channel.query.get_or_404(cid)
    m = ServerMember.query.filter_by(server_id=ch.server_id, user_id=u.id).first()
    if not m or m.role not in ['owner','admin']: return jsonify({'error': 'Brak uprawnień'}), 403
    db.session.delete(ch)
    db.session.commit()
    return jsonify({'success': True})

# ─── MESSAGES ─────────────────────────────────────────────────────────────────

@app.route('/api/channels/<int:cid>/messages')
@token_required
def get_messages(cid):
    u = request.current_user
    ch = Channel.query.get_or_404(cid)
    if not ServerMember.query.filter_by(server_id=ch.server_id, user_id=u.id).first():
        return jsonify({'error': 'Brak dostępu'}), 403
    limit = int(request.args.get('limit', 50))
    before = request.args.get('before')
    q = Message.query.filter_by(channel_id=cid)
    if before:
        q = q.filter(Message.id < int(before))
    messages = q.order_by(Message.created_at.desc()).limit(limit).all()
    return jsonify([msg_dict(m) for m in reversed(messages)])

@app.route('/api/messages/<int:mid>', methods=['DELETE'])
@token_required
def delete_message(mid):
    u = request.current_user
    msg = Message.query.get_or_404(mid)
    if msg.user_id != u.id:
        ch = Channel.query.get(msg.channel_id)
        m = ServerMember.query.filter_by(server_id=ch.server_id, user_id=u.id).first()
        if not m or m.role not in ['owner','admin']:
            return jsonify({'error': 'Brak uprawnień'}), 403
    channel_id = msg.channel_id
    db.session.delete(msg)
    db.session.commit()
    socketio.emit('message_deleted', {'message_id': mid}, room=f'ch_{channel_id}')
    return jsonify({'success': True})

@app.route('/api/messages/<int:mid>', methods=['PATCH'])
@token_required
def edit_message(mid):
    u = request.current_user
    msg = Message.query.get_or_404(mid)
    if msg.user_id != u.id: return jsonify({'error': 'Brak uprawnień'}), 403
    content = request.json.get('content','').strip()
    if not content: return jsonify({'error': 'Treść wymagana'}), 400
    msg.content = content
    msg.edited = True
    msg.edited_at = datetime.utcnow()
    db.session.commit()
    socketio.emit('message_edited', msg_dict(msg), room=f'ch_{msg.channel_id}')
    return jsonify({'success': True})

@app.route('/api/messages/<int:mid>/pin', methods=['POST'])
@token_required
def pin_message(mid):
    u = request.current_user
    msg = Message.query.get_or_404(mid)
    ch = Channel.query.get(msg.channel_id)
    m = ServerMember.query.filter_by(server_id=ch.server_id, user_id=u.id).first()
    if not m or m.role not in ['owner','admin']: return jsonify({'error': 'Brak uprawnień'}), 403
    msg.pinned = not msg.pinned
    db.session.commit()
    return jsonify({'pinned': msg.pinned})

@app.route('/api/messages/<int:mid>/react', methods=['POST'])
@token_required
def react(mid):
    u = request.current_user
    emoji = request.json.get('emoji','')
    existing = Reaction.query.filter_by(message_id=mid, user_id=u.id, emoji=emoji).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(Reaction(message_id=mid, user_id=u.id, emoji=emoji))
    db.session.commit()
    reactions = Reaction.query.filter_by(message_id=mid).all()
    counts = {}
    for r in reactions:
        counts[r.emoji] = counts.get(r.emoji, 0) + 1
    msg = Message.query.get(mid)
    socketio.emit('reactions_updated', {'message_id': mid, 'reactions': counts}, room=f'ch_{msg.channel_id}')
    return jsonify({'reactions': counts})

# ─── FRIENDS & DM ─────────────────────────────────────────────────────────────

@app.route('/api/friends')
@token_required
def get_friends():
    u = request.current_user
    fs = Friendship.query.filter(
        ((Friendship.user_id == u.id) | (Friendship.friend_id == u.id)),
        Friendship.status == 'accepted'
    ).all()
    result = []
    for f in fs:
        fid = f.friend_id if f.user_id == u.id else f.user_id
        u2 = User.query.get(fid)
        unread = DirectMessage.query.filter_by(sender_id=fid, receiver_id=u.id, read=False).count()
        result.append({'id': u2.id, 'username': u2.username, 'avatar_color': u2.avatar_color,
                        'status': u2.status, 'custom_status': u2.custom_status, 'unread': unread, 'friendship_id': f.id})
    return jsonify(result)

@app.route('/api/friends/requests')
@token_required
def friend_requests():
    u = request.current_user
    reqs = Friendship.query.filter_by(friend_id=u.id, status='pending').all()
    result = []
    for r in reqs:
        u2 = User.query.get(r.user_id)
        result.append({'id': r.id, 'user_id': u2.id, 'username': u2.username, 'avatar_color': u2.avatar_color})
    return jsonify(result)

@app.route('/api/friends/add', methods=['POST'])
@token_required
def add_friend():
    u = request.current_user
    username = request.json.get('username','').strip()
    friend = User.query.filter_by(username=username).first()
    if not friend: return jsonify({'error': 'Użytkownik nie znaleziony'}), 404
    if friend.id == u.id: return jsonify({'error': 'Nie możesz dodać siebie'}), 400
    existing = Friendship.query.filter(
        ((Friendship.user_id == u.id) & (Friendship.friend_id == friend.id)) |
        ((Friendship.user_id == friend.id) & (Friendship.friend_id == u.id))
    ).first()
    if existing: return jsonify({'error': 'Zaproszenie już istnieje'}), 400
    db.session.add(Friendship(user_id=u.id, friend_id=friend.id))
    db.session.add(Notification(user_id=friend.id, content=f'{u.username} wysłał Ci zaproszenie do znajomych',
                                 notif_type='friend_request'))
    db.session.commit()
    socketio.emit('friend_request', {'from': u.username, 'from_id': u.id}, room=f'user_{friend.id}')
    return jsonify({'success': True})

@app.route('/api/friends/<int:fid>/accept', methods=['POST'])
@token_required
def accept_friend(fid):
    u = request.current_user
    f = Friendship.query.get_or_404(fid)
    if f.friend_id != u.id: return jsonify({'error': 'Brak uprawnień'}), 403
    f.status = 'accepted'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/<int:fid>/remove', methods=['DELETE'])
@token_required
def remove_friend(fid):
    u = request.current_user
    f = Friendship.query.get_or_404(fid)
    db.session.delete(f)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/dm/<int:friend_id>')
@token_required
def get_dm(friend_id):
    u = request.current_user
    msgs = DirectMessage.query.filter(
        ((DirectMessage.sender_id == u.id) & (DirectMessage.receiver_id == friend_id)) |
        ((DirectMessage.sender_id == friend_id) & (DirectMessage.receiver_id == u.id))
    ).order_by(DirectMessage.created_at).all()
    DirectMessage.query.filter_by(sender_id=friend_id, receiver_id=u.id, read=False).update({'read': True})
    db.session.commit()
    result = []
    for m in msgs:
        result.append({'id': m.id, 'content': m.content, 'sender_id': m.sender_id,
                        'username': m.sender.username, 'avatar_color': m.sender.avatar_color,
                        'created_at': m.created_at.strftime('%H:%M'), 'date': m.created_at.strftime('%d.%m.%Y')})
    return jsonify(result)

@app.route('/api/notifications')
@token_required
def get_notifications():
    u = request.current_user
    notifs = Notification.query.filter_by(user_id=u.id).order_by(Notification.created_at.desc()).limit(20).all()
    return jsonify([{'id': n.id, 'content': n.content, 'type': n.notif_type, 'read': n.read,
                      'created_at': n.created_at.strftime('%H:%M %d.%m')} for n in notifs])

@app.route('/api/notifications/read', methods=['POST'])
@token_required
def mark_notifications_read():
    u = request.current_user
    Notification.query.filter_by(user_id=u.id, read=False).update({'read': True})
    db.session.commit()
    return jsonify({'success': True})

# ─── WEBSOCKET ────────────────────────────────────────────────────────────────

@socketio.on('authenticate')
def on_auth(data):
    import jwt
    try:
        token = data.get('token','')
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        if user:
            join_room(f'user_{user.id}')
            emit('authenticated', {'success': True})
    except:
        emit('authenticated', {'success': False})

@socketio.on('join_channel')
def on_join(data):
    join_room(f"ch_{data['channel_id']}")

@socketio.on('leave_channel')
def on_leave(data):
    leave_room(f"ch_{data['channel_id']}")

@socketio.on('join_dm')
def on_join_dm(data):
    import jwt
    try:
        token = data.get('token','')
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        friend_id = data['friend_id']
        room = f"dm_{min(user_id, friend_id)}_{max(user_id, friend_id)}"
        join_room(room)
    except:
        pass

@socketio.on('send_message')
def handle_message(data):
    import jwt
    try:
        payload = jwt.decode(data.get('token',''), app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        if not user: return
        channel_id = data.get('channel_id')
        content = data.get('content','').strip()
        if not content: return
        ch = Channel.query.get(channel_id)
        if not ch: return
        if not ServerMember.query.filter_by(server_id=ch.server_id, user_id=user.id).first(): return
        msg = Message(content=content, user_id=user.id, channel_id=channel_id,
                      reply_to=data.get('reply_to'))
        db.session.add(msg)
        db.session.commit()
        emit('new_message', msg_dict(msg), room=f'ch_{channel_id}')
    except Exception as e:
        print(f"send_message error: {e}")

@socketio.on('send_dm')
def handle_dm(data):
    import jwt
    try:
        payload = jwt.decode(data.get('token',''), app.config['SECRET_KEY'], algorithms=['HS256'])
        sender = User.query.get(payload['user_id'])
        if not sender: return
        receiver_id = data['receiver_id']
        content = data.get('content','').strip()
        if not content: return
        msg = DirectMessage(content=content, sender_id=sender.id, receiver_id=receiver_id)
        db.session.add(msg)
        db.session.commit()
        room = f"dm_{min(sender.id, receiver_id)}_{max(sender.id, receiver_id)}"
        emit('new_dm', {
            'id': msg.id, 'content': msg.content, 'sender_id': sender.id,
            'username': sender.username, 'avatar_color': sender.avatar_color,
            'created_at': msg.created_at.strftime('%H:%M'), 'date': msg.created_at.strftime('%d.%m.%Y')
        }, room=room)
        emit('dm_notification', {'from': sender.username, 'content': content}, room=f'user_{receiver_id}')
    except Exception as e:
        print(f"send_dm error: {e}")

@socketio.on('typing')
def handle_typing(data):
    import jwt
    try:
        payload = jwt.decode(data.get('token',''), app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        if user:
            emit('user_typing', {'username': user.username, 'channel_id': data['channel_id']},
                 room=f"ch_{data['channel_id']}", include_self=False)
    except:
        pass

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)),
                 allow_unsafe_werkzeug=True)
