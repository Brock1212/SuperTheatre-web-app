from init import db, app

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20))
    pw_hash = db.Column(db.String(64))
    email = db.Column(db.String(64))
    identify = db.column(db.String(64))

class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(30))
    category = db.Column(db.String(20))
    info = db.Column(db.VARCHAR)
    rating = db.Column(db.String(5))
    length = db.Column(db.String(20))
    releasedate = db.Column(db.String(20))
    studio = db.Column(db.String(64))
    cast = db.Column(db.String())
    director = db.Column(db.String(20))
    producer = db.Column(db.String(20))
    screenplay = db.Column(db.String(20))

db.create_all(app = app)