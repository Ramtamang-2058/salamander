import functools

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_migrate import Migrate

from auth.firebase_auth import google_sign_in
from config import FLASK_SECRET_KEY, FIREBASE_CONFIG
from database.db_handler import save_user, save_humanizer, User, Humanizer, db
from processor.humanizer import paraphrase_text

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 7  # 1 week
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)


# Make session permanent by default
@app.before_request
def make_session_permanent():
    session.permanent = True


# Middleware to check if user is authenticated
def login_required(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return wrap


@app.route('/')
def index():
    if 'user' in session:
        user = db.session.get(User, session['user']['uid'])
        if user is None:
            session.clear()
            return redirect(url_for('login'))
        return render_template('dashboard.html', user=user, is_logged_in=True)
    return render_template('dashboard.html', is_logged_in=False)


@app.route('/login')
def login():
    return render_template('login.html', firebase_config=FIREBASE_CONFIG)


@app.route('/auth/google', methods=['POST'])
def google_auth():
    id_token = request.json.get('idToken')
    user_info = google_sign_in(id_token)
    if user_info:
        try:
            uid = user_info.get('uid')
            name = user_info.get('name')
            email = user_info.get('email') or 'human@gmail.com'
            picture = user_info.get('picture', '')
            user = save_user(uid, name, email)

            if not user:
                return jsonify({"status": "error", "message": "Failed to save user"}), 500
            session['user'] = {
                'uid': user.uid,
                'name': user.name,
                'email': user.email,
                'picture': user.picture,
                'is_premium': user.is_premium
            }
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "error", "message": "Invalid token"}), 401


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/api/humanize', methods=['POST'])
@login_required
def humanize_text():
    data = request.get_json()
    breakpoint()
    text = data.get('text', '')
    ultra_mode = data.get('ultra_mode', False)
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    try:
        is_premium = session['user'].get('is_premium', False)
        if ultra_mode and not is_premium:
            return jsonify({'error': 'Ultra Mode requires a premium subscription'}), 403
        result = paraphrase_text(text, ultra_mode=ultra_mode and is_premium)
        save_humanizer(
            session['user']['uid'],
            text,
            result,
            ultra_mode=ultra_mode
        )
        return jsonify({
            'result': result,
            'stats': {
                'readability': 'Excellent' if ultra_mode else 'Good',
                'uniqueness': '97%' if ultra_mode else '85%',
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search_query = request.args.get('search', '', type=str)
        query = Humanizer.query.filter_by(user_id=session['user']['uid'])
        if search_query:
            query = query.filter(Humanizer.input_text.ilike(f'%{search_query}%'))
        humanizers = query.order_by(Humanizer.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        history = [
            {
                'id': h.id,
                'title': h.input_text[:50] + '...' if len(h.input_text) > 50 else h.input_text,
                'humanized_text': h.humanized_text,
                'ultra_mode': False,  # h.ultra_mode
                'created_at': h.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'word_count': len(h.input_text.split())
            }
            for h in humanizers.items
        ]
        return jsonify({
            'history': history,
            'total': humanizers.total,
            'pages': humanizers.pages,
            'current_page': humanizers.page
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/history/<int:humanizer_id>', methods=['DELETE'])
@login_required
def delete_history(humanizer_id):
    try:
        humanizer = db.session.get(Humanizer, humanizer_id)
        if not humanizer or humanizer.user_id != session['user']['uid']:
            return jsonify({'error': 'History item not found or unauthorized'}), 404
        db.session.delete(humanizer)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
