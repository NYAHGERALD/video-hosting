# app.py

from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_cors import CORS
from dotenv import load_dotenv
import os
from models import db, Admin, Passkey, Video
from werkzeug.utils import secure_filename
from auth_routes import auth_bp
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
import moviepy.editor as mp
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo  # Python 3.9+
import boto3
from mimetypes import guess_type
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask import send_file, abort, jsonify


# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
CORS(app)



# Config
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Initialize DB
db.init_app(app)
app.register_blueprint(auth_bp, url_prefix='/auth')

def upload_to_s3(file_path, s3_key, content_type):
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION')
    )
    
    bucket_name = os.getenv('S3_BUCKET')
    
    with open(file_path, 'rb') as f:
        s3.upload_fileobj(f, bucket_name, s3_key, ExtraArgs={'ContentType': content_type})
    
    # Return the full public S3 URL (adjust if private)
    return f"https://{bucket_name}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/{s3_key}"





login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # redirects to login if not authenticated
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))





# Routes
@app.route('/')
def home():
    return redirect(url_for('auth.login'))


s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_REGION')
)




@app.route('/dashboard')
@login_required
def dashboard():
    bucket_name = os.getenv("S3_BUCKET")
    prefix = "videos/"
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    total_likes = 0
    total_dislikes = 0
    videos = []

    for obj in response.get("Contents", []):
        if obj['Key'] == prefix:
            continue

        key = obj['Key']
        filename = key.split('/')[-1]
        title = filename.split('_', 1)[-1].rsplit('.', 1)[0]

        db_video = Video.query.filter_by(video_filename=key).first()
        if not db_video:
            continue

        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': key},
            ExpiresIn=3600
        )

        total_likes += db_video.likes or 0
        total_dislikes += db_video.dislikes or 0

        videos.append({
            'title': title,
            'url': presigned_url,
            'uploaded_at': obj['LastModified'].astimezone(ZoneInfo("America/Chicago")).strftime('%-d %b %Y, %-I:%M %p CT'),
            'size': round(obj['Size'] / (1024 * 1024), 2),
            's3_key': obj['Key'],
            'uuid': db_video.uuid,
            'likes': db_video.likes or 0,
            'dislikes': db_video.dislikes or 0,
        })

    return render_template('dashboard.html', videos=videos, total_likes=total_likes, total_dislikes=total_dislikes)





@app.route('/upload', methods=['POST'])
@login_required
def upload():
    title = request.form['title']
    description = request.form['description']
    video = request.files['video']

    if not video or not title:
        flash("Missing video or title")
        return redirect(url_for('dashboard'))

    video_uuid = uuid.uuid4().hex
    filename = secure_filename(f"{video_uuid}_{video.filename}")
    video_path = os.path.join("/tmp", filename)
    video.save(video_path)

    # Create thumbnail
    clip = mp.VideoFileClip(video_path)
    thumbnail_filename = f"{video_uuid}.png"
    thumbnail_path = os.path.join("/tmp", thumbnail_filename)
    clip.save_frame(thumbnail_path, t=1.0)
    clip.close()

    # Upload both to S3
    video_s3_key = f"videos/{filename}"
    upload_to_s3(video_path, video_s3_key, guess_type(video_path)[0])

    thumbnail_url = upload_to_s3(thumbnail_path, f"thumbnails/{thumbnail_filename}", "image/png")

    # Local timestamp
    local_time = datetime.now(ZoneInfo("America/Chicago"))

    # Save metadata to DB
    new_video = Video(
        uuid=video_uuid,
        title=title,
        description=description,
        video_filename=video_s3_key,  # store S3 key only
        thumbnail_filename=thumbnail_url,
        uploaded_at=local_time
    )
    db.session.add(new_video)
    db.session.commit()

    flash("✅ Video uploaded to S3 successfully.")
    return redirect(url_for('dashboard'))




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        passkey_input = request.form['passkey']

        # Password match check
        if password != confirm_password:
            flash("❌ Passwords do not match.")
            return redirect(url_for('register'))

        # Validate passkey
        valid_key = Passkey.query.filter_by(key=passkey_input, used=False).first()
        if not valid_key:
            flash("❌ Invalid or already used passkey.")
            return redirect(url_for('register'))

        # Check if email is already registered
        if Admin.query.filter_by(email=email).first():
            flash("❌ Email already registered.")
            return redirect(url_for('register'))

        # Hash password and create admin
        hashed_pw = generate_password_hash(password)
        new_admin = Admin(email=email, password_hash=hashed_pw)
        db.session.add(new_admin)

        # Mark passkey as used
        valid_key.used = True
        db.session.commit()

        flash("✅ Admin account created successfully. Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/delete-from-s3', methods=['POST'])
@login_required
def delete_from_s3():
    s3_key = request.form.get('s3_key')
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION')
    )
    bucket_name = os.getenv('S3_BUCKET')
    if s3_key:
        s3.delete_object(Bucket=bucket_name, Key=s3_key)
    flash("✅ Video deleted successfully.")
    return redirect(url_for('dashboard'))





@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        admin = Admin.query.filter_by(email=email).first()
        if not admin or not check_password_hash(admin.password_hash, password):
            flash("❌ Invalid email or password.")
            return redirect(url_for('login'))

        login_user(admin)  # ✅ FLASK-LOGIN logs in the user
        flash("✅ Login successful!")
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("👋 You have been logged out.")
    return redirect(url_for('auth.login'))





# CLI command to init the DB
@app.cli.command("init-db")
def init_db():
    """Initialize the database with all tables."""
    with app.app_context():
        db.create_all()
        print("✅ Database initialized successfully.")


# CLI command to seed a passkey
@app.cli.command("seed_passkey")
def seed_passkey():
    """Insert a default admin passkey into the database."""
    from models import Passkey
    with app.app_context():
        key = "D839F532C1D6C"  # You can change this
        if not Passkey.query.filter_by(key=key).first():
            passkey = Passkey(key=key)
            db.session.add(passkey)
            db.session.commit()
            print(f"✅ Passkey '{key}' seeded successfully.")
        else:
            print(f"⚠️ Passkey '{key}' already exists.")


@app.route('/watch/<video_uuid>')
def public_video_view(video_uuid):
    video = Video.query.filter_by(uuid=video_uuid).first()
    if not video:
        return abort(404)

    return render_template('player.html', video=video)

@app.route('/video/<uuid>')
def player(uuid):
    video = Video.query.filter_by(uuid=uuid).first_or_404()

    presigned_url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': os.getenv("S3_BUCKET"), 'Key': video.video_filename},
        ExpiresIn=3600
    )

    return render_template('player.html', video=video, video_url=presigned_url)




@app.route('/video/<uuid>/counts', methods=['GET'])
def get_video_vote_counts(uuid):
    video = Video.query.filter_by(uuid=uuid).first_or_404()
    return jsonify({
        'likes': video.likes or 0,
        'dislikes': video.dislikes or 0
    })





from models import Video, VideoVote  # Make sure both are imported

@app.route('/video/<uuid>/vote', methods=['POST'])
def vote_video(uuid):
    data = request.get_json()
    vote_type = data.get('vote')  # 'like' or 'dislike'
    previous_vote = data.get('previous')  # like or dislike or null
    device_id = request.remote_addr

    if vote_type not in ['like', 'dislike']:
        return jsonify({'error': 'Invalid vote type'}), 400

    video = Video.query.filter_by(uuid=uuid).first_or_404()
    existing_vote = VideoVote.query.filter_by(video_uuid=uuid, device_id=device_id).first()

    # If they voted before, we switch their vote
    if existing_vote:
        if existing_vote.vote_type == vote_type:
            return jsonify({'error': 'You already voted this way'}), 403

        # Reverse the old vote
        if existing_vote.vote_type == 'like':
            video.likes = max((video.likes or 1) - 1, 0)
        elif existing_vote.vote_type == 'dislike':
            video.dislikes = max((video.dislikes or 1) - 1, 0)

        # Apply the new vote
        if vote_type == 'like':
            video.likes = (video.likes or 0) + 1
        else:
            video.dislikes = (video.dislikes or 0) + 1

        existing_vote.vote_type = vote_type  # update the vote type
    else:
        # First-time vote
        if vote_type == 'like':
            video.likes = (video.likes or 0) + 1
        else:
            video.dislikes = (video.dislikes or 0) + 1

        new_vote = VideoVote(video_uuid=uuid, device_id=device_id, vote_type=vote_type)
        db.session.add(new_vote)

    db.session.commit()

    return jsonify({
        'likes': video.likes or 0,
        'dislikes': video.dislikes or 0
    })





if __name__ == '__main__':
    app.run(debug=True)

