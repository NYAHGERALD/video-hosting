# models.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


db = SQLAlchemy()

def generate_uuid():
    return uuid.uuid4().hex

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)
    # ✅ OPTIONAL, but just to be safe:
    @property
    def is_active(self):
        return True

class Passkey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(64), unique=True, default=generate_uuid)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    video_filename = db.Column(db.String(255), nullable=False)
    thumbnail_filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)


class VideoVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_uuid = db.Column(db.String(64), db.ForeignKey('video.uuid'), nullable=False)
    device_id = db.Column(db.String(128), nullable=False)
    vote_type = db.Column(db.String(10), nullable=False)  # 'like' or 'dislike'
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)
