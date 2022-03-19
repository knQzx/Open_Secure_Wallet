import hashlib
import random

import requests
import telebot
from bit import Key
from bitcoinaddress import Wallet
from cryptography.fernet import Fernet
from flask import render_template, request, redirect, session

import address
from api import db, app, Users


class Wallets(db.Model):  # => Wallets db
    __tablename__ = "wallets"
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    wallet = db.Column(db.String, nullable=True)
    password_words = db.Column(db.String, nullable=True)

    def __repr__(self):
        return f'<{self.id}>'


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    words = ['ежедневник', 'субботник', 'календарь', 'пузырь', 'леопард', 'сауна',
             'режим', 'бензопила', 'созвездие', 'бутафория', 'барокко', 'аббревиатура',
             'иллюстрация', 'переводчик', 'ириска', 'Фантастика', 'тхэквондо', 'радар',
             'акция', 'абонемент', 'солярий', 'аристократ', 'лавина', 'тир', 'венера',
             'марс', 'сила', 'море', 'океан', 'яндекс', 'гугл', 'глобус']
    words = '_'.join(random.sample(words, 24))
    return render_template('login.html', words=words, what='Registration',
                           key_fernet=(Fernet.generate_key()).decode())


@app.route('/registration_2/<words>/<key_fernet>', methods=['GET', 'POST'])
def registration_2(words, key_fernet):
    if len(request.form["password"]) <= 8:
        return redirect('/registration')
    return redirect(f'/todo/api/v1.0/registration/{request.form["password"]}/{words}/{key_fernet}')


@app.route('/authentication', methods=['GET', 'POST'])
def authentication():
    red = f'/todo/api/v1.0/authentication/{request.form["password"]}/{request.form["words"]}/{request.form["key_fernet"]}'
    if request.method == 'POST':
        return redirect(red)
    return render_template('login.html', what='Authentication')


@app.route('/', methods=['GET', 'POST'])
def index():
    return redirect('/personal_account')


@app.route('/personal_account', methods=['GET', 'POST'])
def personal_account():
    elements_nav = [
        'nav-item nav-link active',
        'nav-item nav-link',
        'nav-item nav-link']
    if 'hash_password_words' in session and 'password' in session and 'words' in session:
        if request.method == 'POST':
            return render_template('personal_account.html', elements_nav=elements_nav,
                                   password_user=session['password'], words_user=session['words'],
                                   hash_password_words=session['hash_password_words'],
                                   key_fernet=session['key_fernet'], editing='True', action='/save')
        return render_template('personal_account.html', elements_nav=elements_nav,
                               password_user=session['password'], words_user=session['words'],
                               hash_password_words=session['hash_password_words'],
                               key_fernet=session['key_fernet'])
    else:
        return redirect('/authentication')


@app.route('/update_password/<password_start>/<secretWords>/<key>/<new_password>')
def update_password(password_start, secretWords, key, new_password):
    # create tables
    db.create_all()
    # old_values
    old_hash_password = f"{hashlib.md5(str(password_start).encode()).hexdigest()}"
    old_hash_words = f"{hashlib.md5(f'{secretWords}{old_hash_password}'.encode()).hexdigest()}"
    model = Users.query.filter_by(password=old_hash_password, words=old_hash_words).first()
    # make new values and to db
    # make new hash_password
    hash_password = f"{hashlib.md5(str(new_password).encode()).hexdigest()}"
    # make hash_words
    hash_words = f"{hashlib.md5(f'{secretWords}{hash_password}'.encode()).hexdigest()}"
    # make hash_password_words
    hash_password_words = f"{hashlib.md5(f'{hash_password}{hash_words}'.encode()).hexdigest()}"
    # make hash_key
    hash_key = f"{hashlib.md5(f'{hash_password}{key}'.encode()).hexdigest()}"
    model.password = hash_password
    model.words = hash_words
    model.key_fernet = hash_key
    model.password_words = hash_password_words
    # edit session data
    session['password'] = new_password
    session['words'] = secretWords
    session['hash_password_words'] = hash_password_words
    session['key_fernet'] = key
    db.session.commit()
    return redirect('/personal_account')


@app.route('/wallets', methods=['GET', 'POST'])
def wallets():
    if 'hash_password_words' in session and 'password' in session and 'words' in session:
        elements_nav = [
            'nav-item nav-link',
            'nav-item nav-link active',
            'nav-item nav-link']
        db.create_all()
        list_wallets = []
        for el in (Wallets.query.filter_by(password_words=session['hash_password_words'])):
            list_wallets.append(el.wallet)
        return render_template('wallets.html', elements_nav=elements_nav, list_wallets=list_wallets)
    else:
        return redirect('/authentication')


@app.route('/wallet/<WALLET>', methods=['GET', 'POST'])
def wallet_info(WALLET):
    # db create all
    db.create_all()
    key_bytes = str(session['key_fernet']).encode()
    f = Fernet(key_bytes)
    # decode_wallet
    decode_wallet = WALLET
    # WALLET decrypt
    WALLET = f.decrypt(WALLET.encode()).decode()
    wallet = requests.get(f'{address.address}/todo/api/v1.0/get_wallet/{WALLET}').json()
    elements_nav = [
        'nav-item nav-link',
        'nav-item nav-link active',
        'nav-item nav-link']
    return render_template('separate_wallet.html', elements_nav=elements_nav,
                           address_wallet=wallet['public_address'], wallet=wallet['wallet'],
                           decode_wallet=decode_wallet, balances=wallet['balances'],
                           address=address.address)


@app.route('/get_btc/<DECODE_WALLET>', methods=['GET', 'POST'])
def get_btc(DECODE_WALLET):
    # key bytes fernet key
    db.create_all()
    key_bytes = str(session['key_fernet']).encode()
    f = Fernet(key_bytes)
    #
    WALLET = f.decrypt(DECODE_WALLET.encode()).decode()
    # wallet address
    wallet = requests.get(f'{address.address}/todo/api/v1.0/get_wallet/{WALLET}').json()
    # wallet
    wallet_public_address = wallet['public_address']
    # make qr-code
    elements_nav = [
        'nav-item nav-link',
        'nav-item nav-link active',
        'nav-item nav-link']
    href = f'https://api.qrserver.com/v1/create-qr-code/?data=bitcoin:{wallet_public_address}&amp'
    return render_template('separate_wallet.html', wallet=WALLET, elements_nav=elements_nav,
                           access='qr', decode_wallet=DECODE_WALLET,
                           src_url=href,
                           address=address.address)


@app.route('/send_btc/<DECODE_WALLET>', methods=['GET', 'POST'])
def send_btc(DECODE_WALLET):
    if request.method == 'POST':
        # address to send
        address_to_send = request.form['address_to_send']
        # how much to send
        how_much = request.form['quantity']
        # key bytes fernet key
        db.create_all()
        key_bytes = str(session['key_fernet']).encode()
        f = Fernet(key_bytes)
        WALLET = f.decrypt(DECODE_WALLET.encode()).decode()
        # wallet address
        wallet = requests.get(f'{address.address}/todo/api/v1.0/get_wallet/{WALLET}').json()
        # wallet_balance
        wallet_balance = wallet['balances']['btc']
        # nav bar
        elements_nav = [
            'nav-item nav-link',
            'nav-item nav-link active',
            'nav-item nav-link']
        if float(wallet_balance) < float(request.form['quantity']):
            return render_template('send_wallet.html', from_send=wallet['wallet'], wallet=WALLET,
                                   elements_nav=elements_nav, balances=wallet['balances'],
                                   decode_wallet=DECODE_WALLET, address=address.address,
                                   error='Not enough funds')
        elif float(wallet_balance) >= float(request.form['quantity']):
            wallet_2 = Wallet(WALLET)
            my_key = Key(wallet_2.testnet)
            try:
                my_key.send([(address_to_send, float(how_much), 'btc')])
                return render_template('send_wallet.html', from_send=wallet['wallet'],
                                       wallet=WALLET,
                                       elements_nav=elements_nav, balances=wallet['balances'],
                                       decode_wallet=DECODE_WALLET, address=address.address,
                                       error='SUCCESS!')
            except BaseException:
                return render_template('send_wallet.html', from_send=wallet['wallet'],
                                       wallet=WALLET,
                                       elements_nav=elements_nav, balances=wallet['balances'],
                                       decode_wallet=DECODE_WALLET, address=address.address,
                                       error='Transactions must have at least one unspent.')
    # key bytes fernet key
    db.create_all()
    key_bytes = str(session['key_fernet']).encode()
    f = Fernet(key_bytes)
    # decrypt wallet
    WALLET = f.decrypt(DECODE_WALLET.encode()).decode()
    # wallet address
    wallet = requests.get(f'{address.address}/todo/api/v1.0/get_wallet/{WALLET}').json()
    # nav bar
    elements_nav = [
        'nav-item nav-link',
        'nav-item nav-link active',
        'nav-item nav-link']
    return render_template('send_wallet.html', from_send=wallet['wallet'], wallet=WALLET,
                           elements_nav=elements_nav, balances=wallet['balances'],
                           access='qr', decode_wallet=DECODE_WALLET, address=address.address)


@app.route('/create_wallet', methods=['GET', 'POST'])
def create_wallet():
    # create tables
    db.create_all()
    # create new wallet
    wallet = Wallet()
    # to str
    key_wallet = str(wallet.key.hex)
    # encode key
    bytes_key = Fernet(str(session['key_fernet']).encode())
    encrypted_message = bytes_key.encrypt(key_wallet.encode())
    # wallet key bytes to str
    wallet_key = str(encrypted_message.decode())
    # new example wallets
    new_wallet = Wallets(wallet=wallet_key, password_words=session['hash_password_words'])
    # add to db
    db.session.add(new_wallet)
    # commit => save
    db.session.commit()
    return redirect('/wallets')


@app.route('/delete_wallet/<wallet>', methods=['GET', 'POST'])
def delete_wallet(wallet):
    wallet = requests.get(f'{address.address}/todo/api/v1.0/get_wallet/{wallet}').json()
    elements_nav = [
        'nav-item nav-link',
        'nav-item nav-link active',
        'nav-item nav-link']
    if float(request.args.get('btc')) >= 0.000000012:
        return render_template('separate_wallet.html', elements_nav=elements_nav,
                               access='delete_or_no', address_wallet=wallet['public_address'],
                               wallet=wallet['wallet'], balances=wallet['balances'],
                               address=address.address)
    else:
        key_bytes = str(session['key_fernet']).encode()
        f = Fernet(key_bytes)
        list_wallets = {}
        for el in (Wallets.query.filter_by(password_words=session['hash_password_words'])):
            list_wallets[(f.decrypt((el.wallet).encode()).decode())] = el.wallet
        if wallet['wallet'] in list_wallets:
            wallet_address_hash = (list_wallets[wallet['wallet']])
            Wallets.query.filter_by(wallet=wallet_address_hash).delete()
            # commit => save
            db.session.commit()
        return redirect('/wallets')


@app.route('/support', methods=['GET', 'POST'])
def support():
    if 'hash_password_words' in session and 'password' in session and 'words' in session:
        elements_nav = [
            'nav-item nav-link',
            'nav-item nav-link',
            'nav-item nav-link active']
        return redirect('/faq/getting_started')
    else:
        return redirect('/authentication')


@app.route('/faq/<METHOD>', methods=['GET', 'POST'])
def faq(METHOD):
    if 'hash_password_words' in session and 'password' in session and 'words' in session:
        elements_nav = [
            'nav-item nav-link',
            'nav-item nav-link',
            'nav-item nav-link active']
        if METHOD == 'getting_started':
            return render_template('FAQ.html', elements_nav=elements_nav, METHOD='getting_started')
        elif METHOD == 'get_and_login':
            return render_template('FAQ.html', elements_nav=elements_nav, METHOD='get_and_login')
        elif METHOD == 'wallet_managment':
            return render_template('FAQ.html', elements_nav=elements_nav, METHOD='wallet_managment')
        elif METHOD == 'ask_question':
            if request.method == 'POST':
                bot = telebot.TeleBot('5153960181:AAFYzT1rs4DTcyqs_XWMwLOwXsZDCsqHLTo')
                answer = f'Telegram: {request.form["telegram"]}\n\nQuestion: {request.form["question"]}'
                bot.send_message(763258583, answer)
                return render_template('FAQ.html', elements_nav=elements_nav, METHOD='ask_question',
                                       message='sent')
            return render_template('FAQ.html', elements_nav=elements_nav, METHOD='ask_question')
    else:
        return redirect('/authentication')


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
