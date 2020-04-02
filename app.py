from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float
import os
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy_utils import force_instant_defaults


dab_app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
dab_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'dab.db')
dab_app.config['JWT_SECRET_KEY'] = 'super-secret'  # CHANGE IN REAL LIFE
dab_app.config['MAIL_SERVER']= 'smtp.mailtrap.io'
dab_app.config['MAIL_PORT'] = 2525
dab_app.config['MAIL_USERNAME'] = '92247fa7203e59'
dab_app.config['MAIL_PASSWORD'] = '4a79d4c7f59037'
dab_app.config['MAIL_USE_TLS'] = True
dab_app.config['MAIL_USE_SSL'] = False

db = SQLAlchemy(dab_app)
ma = Marshmallow(dab_app)
jwt = JWTManager(dab_app)
mail = Mail(dab_app)

#force_instant_defaults()


@dab_app.cli.command('db_create')
def db_create():
    db.create_all()
    print('Database created!')


@dab_app.cli.command('db_drop')
def db_drop():
    db.drop_all()
    print('Database dropped!')


@dab_app.cli.command('db_seed')
def db_seed():
    userA = User(first_name='Lenni',
                 last_name='Hume',
                 username='LenniGirl',
                 email='lenni@dogmail.com',
                 password_hash=generate_password_hash('woof'))

    userB = User(first_name='Carl',
                 last_name='Hume',
                 username='MrCarl',
                 email='carl@catmail.com',
                 password_hash=generate_password_hash('meow'))

    userC = User(first_name='Rizzo',
                 last_name='Hume',
                 username='LittleOne',
                 email='rizzo@catmail.com',
                 password_hash=generate_password_hash('carl'))
    db.session.add(userA)
    db.session.add(userB)
    db.session.add(userC)

    listingA = Listing(listing_title='Christmas Card',
                       sku=111111,
                       category='Holiday',
                       price=5.50)

    listingB = Listing(listing_title='Quarantine Card',
                       sku=222222,
                       category='Hello',
                       price=6.50)

    listingC = Listing(listing_title='Birthday Card',
                       sku=333333,
                       category='Birthday')

    db.session.add(listingA)
    db.session.add(listingB)
    db.session.add(listingC)
    db.session.commit()
    print('Database Seeded!')


@dab_app.route('/not_found')
def not_found():
    return jsonify(message='That resource was not found'), 404


@dab_app.route('/display_users', methods=['GET'])
def display_users():
    users_list = User.query.all()
    print(users_list)
    result = users_schema.dump(users_list)
    return jsonify(result)


@dab_app.route('/register_user', methods=['POST'])
def register_user():
    email = request.form['email']
    test = User.query.filter_by(email=email).first()
    if test:
        return jsonify(message='An account for that email already exists'), 409
    else:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        password = request.form['password']
        unprocessed_phone = request.form['phone']
        phone = unprocessed_phone.replace('(', '').replace(')', '').replace('-', '').replace(' ', '').replace('.', '')
        if phone.isdigit():
            try:
                user = User(first_name=first_name, last_name=last_name, username=username, email=email,
                            phone=int(phone), password_hash=generate_password_hash(password))
                db.session.add(user)
                db.session.commit()
                return jsonify(message="New user account has been successfully created."), 201
            except:
                return jsonify({'error': 'An error occurred saving the user to the database'}), 500
        else:
            try:
                user = User(first_name=first_name, last_name=last_name, username=username, email=email,
                            password_hash=generate_password_hash(password))
                db.session.add(user)
                db.session.commit()
                return jsonify(message="New user account has been successfully created."), 201
            except:
                return jsonify({'error': 'An error occurred saving the user to the database'}), 500


@dab_app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        #email = request.json['email']
        username = request.json['username']
        hashed_password = request.json['password']
    else:
        #email = request.form['email']
        username = request.form['username']
        hashed_password = request.form['password']

    clear_password = check_password_hash(hashed_password)
    login_check = User.query.filter_by(username=username, password=clear_password).first()
    if login_check:
        access_token = create_access_token(identity=email)
        return jsonify(message="Login succeeded!", access_token=access_token)
    else:
        return jsonify(message="Bad email or password"), 401


# @dab_app.route('/retrieve_password/<string:email>', methods=['GET'])
# def retrieve_password(email: str):
#     user = User.query.filter_by(email=email).first()
#     if user:
#         msg = Message("your password is " + user.password,
#                       sender= "admin@my-api.com",
#                       recipients=[email])
#         mail.send(msg)
#         return jsonify(message="Password sent to " + email)
#     else:
#         return jsonify(message="That email doesn't exist"), 401


# @dab_app.route('/log_details/<int:log_id>', methods=['GET'])
# def log_details(log_id: int):
#     log = Log.query.filter_by(log_id=log_id).first()
#     if log:
#         result = log_schema.dump(log)
#         return jsonify(result)
#     else:
#         return jsonify(message="That log doesn't exist"), 404


@dab_app.route('/add_log', methods=['POST'])
@jwt_required
def add_listing():
    listing_title = request.form['listing_title']
    sku = request.form['sku']
    sku_check = Listing.query.filter_by(sku=sku).first()
    title_check = Listing.query.filter_by(listing_title=listing_title).first()
    if sku_check:
        return jsonify("That SKU is already in use.")
    elif title_check:
        return jsonify("There is already a listing for that item.")
    else:
        listing_title = request.form['listing_title']
        sku = request.form['sku']
        category = request.form['category']

        new_listing = Listing(listing_title=listing_title,
                              sku=sku,
                              category=category)
        db.session.add(new_listing)
        db.session.commit()
        return jsonify(message="New listing added"), 201


@dab_app.route('/update_listing', methods=['PUT'])
@jwt_required
def update_listing():
    sku = int(request.form['sku'])
    listing = Listing.query.filter_by(sku=sku).first()
    if listing:
        listing.listing_title = request.form['listing_title']
        listing.sku = int(request.form['sku'])
        listing.category = request.form['category']
        listing.sales_count = int(request.form['sales_count'])
        db.session.add(listing)
        db.session.commit()
        return jsonify(messdage="Listing successfully updated!"), 202
    else:
        return jsonify(message="That SKU does not exist"), 404


@dab_app.route('/update_user_access', methods=['PUT'])
@jwt_required
def update_user_access():
    username = request.form['username']
    user = Listing.query.filter_by(username=username).first()
    if user:
        if user.access_tier < 3:
            user.access_tier = 2
            db.session.add(user)
            db.session.commit()
            return jsonify(messdage="User access tier modified to TIER TWO-USER."), 202
        else:
            return jsonify(messdage="Unable to downgrade user access.."), 403
    else:
        return jsonify(message="User does not exist"), 404


@dab_app.route('/remove_listing/<int:sku>', methods=['DELETE'])
@jwt_required
def remove_listing(sku: int):
    listing = Listing.query.filter_by(sku=sku).first()
    if listing:
        db.session.delete(listing)
        db.session.commit()
        return jsonify(message="Listing has been successfully deleted."), 202
    else:
        return jsonify(message="Listing does not exist."), 404


@dab_app.route('/add_image', methods=['POST'])
@jwt_required
def add_image():
    file_name = request.form['file_name']
    file_name_check = Listing.query.filter_by(file_name=file_name).first()
    if file_name_check:
        return jsonify("That image has already been uploaded."), 409
    else:
        listing_sku = request.form['listing_sku']
        img_path = request.form['img_path']
        new_image = Image(file_name=file_name,
                          listing_sku=listing_sku,
                          img_path=img_path)
        db.session.add(new_image)
        db.session.commit()
        return jsonify(message="New image added"), 201


# database models
class Listing(db.Model):
    __tablename__ = 'listings'
    sku = Column(Integer, unique=True, nullable=False, primary_key=True)
    #listing_id = Column(Integer, primary_key=True)
    listing_title = Column(String(140), nullable=False)
    category = Column(String(20), nullable=False)
    price = Column(Float, default=99.99)
    sales_count = Column(Integer, default=0)


class Image(db.Model):
    __tablename__ = 'images'
    img_id = Column(Integer, primary_key=True)
    file_name = Column(String, nullable=False, unique=True)
    listing_sku = Column(Integer, db.ForeignKey('listings.sku'), nullable=False, foreign_key=True)
    img_path = Column(String, nullable=False)


class User(db.Model):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    first_name = Column(String(16), nullable=False)
    last_name = Column(String(16), nullable=False)
    username = Column(String(16), nullable=False, unique=True)
    email = Column(String(40), unique=True, nullable=False)
    phone = Column(Integer)
    password_hash = Column(String(128), nullable=False)
    access_tier = Column(Integer, default=1)


# class AccessLevel(Enum):
#     VISITOR = 1
#     USER = 2
#     ADMIN = 3
#     GOD = 4


class ListingSchema(ma.Schema):
    class Meta:
        fields = ('listing_id', 'listing_title', 'sku', 'email', 'category', 'price', 'sales_count')


class ImageSchema(ma.Schema):
    class Meta:
        fields = ('img_id', 'listing_id', 'img_path')


class UserSchema(ma.Schema):
    class Meta:
        fields = ('user_id', 'first_name', 'last_name', 'username', 'email', 'phone', 'password_hash', 'access_tier')


listing_schema = ListingSchema()
listings_schema = ListingSchema(many=True)

img_schema = ImageSchema()
imgs_schema = ImageSchema(many=True)

user_schema = UserSchema()
users_schema = UserSchema(many=True)

if __name__ == '__main__':
    dab_app.run()
