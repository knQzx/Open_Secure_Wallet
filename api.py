import hashlib

from bit import Key
from bitcoinaddress import Wallet
from flask import redirect, jsonify, Flask, session
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy

from address import database_address, secret_key

app = Flask(__name__)
db = SQLAlchemy(app)
api = Api(app)

app.config['SQLALCHEMY_DATABASE_URI'] = database_address
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secret_key


class Users(db.Model):  # => Users db
    __tablename__ = "users"
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    password = db.Column(db.String, nullable=True)
    words = db.Column(db.String, nullable=True)
    key_fernet = db.Column(db.String, nullable=True)
    password_words = db.Column(db.String, nullable=True)

    def __repr__(self):
        return f'<{self.id}>'


class Registration(Resource):
    def get(self, PASSWORD, WORDS, key_fernet):
        # create tables
        db.create_all()
        # make hash_password
        hash_password = f"{hashlib.md5(str(PASSWORD).encode()).hexdigest()}"
        # make hash_words
        hash_words = f"{hashlib.md5(f'{WORDS}{hash_password}'.encode()).hexdigest()}"
        # make hash_password_words
        hash_password_words = f"{hashlib.md5(f'{hash_password}{hash_words}'.encode()).hexdigest()}"
        # make hash_key
        hash_key = f"{hashlib.md5(f'{hash_password}{key_fernet}'.encode()).hexdigest()}"
        # if there is no data of our user in the table
        if Users.query.filter_by(password=hash_password, words=hash_words).first() is None:
            # create example
            new_user = Users(password=hash_password, words=hash_words,
                             password_words=hash_password_words, key_fernet=hash_key)
            # add to db
            db.session.add(new_user)
            # commit => save
            db.session.commit()
            # to session
            session['password'] = PASSWORD
            session['words'] = WORDS
            session['hash_password_words'] = hash_password_words
            session['key_fernet'] = key_fernet
            return redirect('/personal_account')
        return redirect('/registration')


class Authentication(Resource):
    def get(self, PASSWORD, WORDS, key_fernet):
        # create tables
        db.create_all()
        # make hash_password
        hash_password = f"{hashlib.md5(str(PASSWORD).encode()).hexdigest()}"
        # make hash_words
        hash_words = f"{hashlib.md5(f'{WORDS}{hash_password}'.encode()).hexdigest()}"
        # make hash_password_words
        hash_password_words = f"{hashlib.md5(f'{hash_password}{hash_words}'.encode()).hexdigest()}"
        # make hash_key
        hash_key = f"{hashlib.md5(f'{hash_password}{key_fernet}'.encode()).hexdigest()}"
        # if there is no data of our user in the table
        if Users.query.filter_by(password=hash_password, words=hash_words).first() is not None:
            # get info about user
            session['password'] = PASSWORD
            session['words'] = WORDS
            session['hash_password_words'] = hash_password_words
            session['key_fernet'] = key_fernet
            return redirect('/personal_account')
        return redirect('/authentication')


class Get_Wallet_Info(Resource):
    def get(self, WALLET):
        wallet = Wallet(WALLET)
        list_data = f'{wallet.key}'.split()
        wallet_key = (list_data[list_data.index('WIF:') + 1])
        my_key = Key(wallet_key)
        usd_balance = my_key.get_balance('usd')
        eur_balance = my_key.get_balance('eur')
        btc_balance = my_key.get_balance('btc')
        public_address = my_key.address
        return jsonify({'wallet': WALLET, 'public_address': public_address,
                        'balances': {'usd': usd_balance, 'eur': eur_balance, 'btc': btc_balance}})

    
class Update_User_Settings(Resource):
    def get(self, PASSWORD, WORDS, key_fernet, what_to_see):
        return redirect(f'/update_user_settings/<PASSWORD>/<WORDS>/<key_fernet>&what_to_see={what_to_see}')

api.add_resource(Registration, '/todo/api/v1.0/registration/<PASSWORD>/<WORDS>/<key_fernet>',
                 endpoint='registration_1')
api.add_resource(Authentication, '/todo/api/v1.0/authentication/<PASSWORD>/<WORDS>/<key_fernet>',
                 endpoint='authentication_2')
api.add_resource(Get_Wallet_Info, '/todo/api/v1.0/get_wallet/<WALLET>', endpoint='wallet_2')
api.add_resource(Update_User_Settings, '/todo/api/v1.0/update_settings/<PASSWORD>/<WORDS>/<key_fernet>/<what_to_see>', endpoint='update_2')
