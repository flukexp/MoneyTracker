from flask.cli import FlaskGroup

from app import app, db
from app.models.contact import Contact
from app.models.authuser import AuthUser, PrivateContact

from werkzeug.security import generate_password_hash

cli = FlaskGroup(app)

@cli.command("create_db")
def create_db():
    db.drop_all()
    db.create_all()
    db.session.commit()

@cli.command("seed_db")
def seed_db():
    db.session.add(
        Contact(firstname='สมชาย', lastname='ทรงแบด', phone='081-111-1111'))
    db.session.add(AuthUser(email="admin@204212", name='admin',
                            password=generate_password_hash('1234',
                                                            method='sha256'),
                            avatar_url='https://ui-avatars.com/api/?name=\
                            admin&background=83ee03&color=fff'))
    db.session.add(
       PrivateContact(firstname='admin', lastname='',
                      phone='099-999-999', owner_id=1))
    db.session.commit()

if __name__ == "__main__":
    cli()