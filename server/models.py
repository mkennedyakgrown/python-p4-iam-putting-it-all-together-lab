from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship(
        'Recipe', back_populates='user', cascade='all, delete-orphan')

    @validates('username')
    def validate_username(self, key, name):
        if name == '':
            raise ValueError('Username cannot be an empty string')
        elif self.query.filter_by(username=name).first() is not None:
            raise ValueError('This name already exists')
        else:
            return name

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))
    
    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, db.CheckConstraint('LENGTH(instructions) >= 50)'), nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship(
    'User', back_populates='recipes', uselist=False)

    __table_args__ = (db.CheckConstraint('LENGTH(instructions) >= 50'),)

    @validates('title')
    def validate_title(self, key, title_text):
        if title_text == '':
            raise ValueError('Title cannot be an empty string')
        else:
            return title_text
        
    @validates('instructions')
    def validate_instructions(self, key, inst):
        if inst == '':
            raise ValueError('Instructions cannot be an empty string')
        # elif len(inst) < 50:
        #     raise ValueError('Instructions must be at least 50 characters long')
        else:
            return inst