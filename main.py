import os
import random
import secrets

import qrcode
import requests
from bitcoinaddress import Wallet
from cryptography.fernet import Fernet
from flask import render_template, request, redirect, session

import address
from api import db, app


class Wallets(db.Model):  # => Wallets db
    __tablename__ = "wallets"
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    wallet = db.Column(db.String, nullable=True)
    password_words = db.Column(db.String, nullable=True)

    def __repr__(self):
        return f'<{self.id}>'


# TODO: registration
@app.route('/registration', methods=['GET', 'POST'])
def registration():
    words = ['ежедневник', 'субботник', 'календарь', 'пузырь', 'леопард', 'сауна',
             'режим', 'бензопила', 'созвездие', 'бутафория', 'барокко', 'аббревиатура',
             'иллюстрация', 'переводчик', 'ириска', 'Фантастика', 'тхэквондо', 'радар',
             'акция', 'абонемент', 'солярий', 'аристократ', 'лавина', 'тир', 'венера',
             'марс', 'сила', 'море', 'океан', 'яндекс', 'гугл', 'глобус']
    words = '_'.join(random.sample(words, 24))
    return render_template('registration.html', words=words, what='Registration',
                           key_fernet=(Fernet.generate_key()).decode())


@app.route('/registration_2/<words>/<key_fernet>', methods=['GET', 'POST'])
def registration_2(words, key_fernet):
    if len(request.form["password"]) <= 8:
        return redirect('/registration')
    return redirect(f'/todo/api/v1.0/registration/{request.form["password"]}/{words}/{key_fernet}')


# TODO: authentication
@app.route('/authentication', methods=['GET', 'POST'])
def authentication():
    if request.method == 'POST':
        return redirect(
            f'/todo/api/v1.0/authentication/{request.form["password"]}/{request.form["words"]}/{request.form["key_fernet"]}')
    return render_template('registration.html', what='Authentication')


@app.route('/', methods=['GET', 'POST'])
def index():
    return redirect('/personal_account')


@app.route('/personal_account', methods=['GET', 'POST'])
def personal_account():
    print(session)
    elements_nav = [
        'nav-item nav-link active',
        'nav-item nav-link',
        'nav-item nav-link',
        'nav-item nav-link']
    if 'hash_password_words' in session and 'password' in session and 'words' in session:
        print(request.method)
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


@app.route('/personal_account/save', methods=['GET', 'POST'])
def personal_account_save():
    if request.method == 'POST':
        print(session)
        return redirect('/personal_account')


@app.route('/wallets', methods=['GET', 'POST'])
def wallets():
    if 'hash_password_words' in session and 'password' in session and 'words' in session:
        elements_nav = [
            'nav-item nav-link',
            'nav-item nav-link active',
            'nav-item nav-link',
            'nav-item nav-link']
        db.create_all()
        key_bytes = str(session['key_fernet']).encode()
        f = Fernet(key_bytes)
        list_wallets = []
        for el in (Wallets.query.filter_by(password_words=session['hash_password_words'])):
            # print((f.decrypt((el.wallet).encode())).decode())
            # print(el.password_words)
            list_wallets.append(f.decrypt((el.wallet).encode()).decode())
        return render_template('wallets.html', elements_nav=elements_nav, list_wallets=list_wallets)
    else:
        return redirect('/authentication')


@app.route('/wallet/<WALLET>', methods=['GET', 'POST'])
def wallet_info(WALLET):
    wallet = requests.get(f'{address.address}/todo/api/v1.0/get_wallet/{WALLET}').json()
    print(wallet)
    elements_nav = [
        'nav-item nav-link',
        'nav-item nav-link active',
        'nav-item nav-link',
        'nav-item nav-link']
    return render_template('separate_wallet.html', elements_nav=elements_nav,
                           address_wallet=wallet['public_address'], wallet=wallet['wallet'],
                           balances=wallet['balances'], address=address.address)


@app.route('/get_btc/<WALLET>', methods=['GET', 'POST'])
def get_btc(WALLET):
    # create token for get access to qr-code
    new_key = secrets.token_hex(10)
    # wallet address
    wallet = requests.get(f'{address.address}/todo/api/v1.0/get_wallet/{WALLET}').json()
    # wallet
    wallet_public_address = wallet['public_address']
    # make qr-code
    img = qrcode.make(f'bitcoin:{wallet_public_address}')
    img.save(f"qr/{new_key}.png")
    # upload to cloud service
    with open(f"qr/{new_key}.png", "rb") as file:
        url = "https://api.imgbb.com/1/upload"
        payload = {
            "key": '7fc9d9ef94adb806ff9d40319ddc8f8a',
            "image": __import__('base64').b64encode(file.read()),
        }
        res = requests.post(url, payload)
        elements_nav = [
            'nav-item nav-link',
            'nav-item nav-link active',
            'nav-item nav-link',
            'nav-item nav-link']
        return render_template('separate_wallet.html', wallet=WALLET, elements_nav=elements_nav,
                               access='qr', src_url=res.json()['data']['url'],
                               address=address.address), os.remove(f"qr/{new_key}.png")


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
        'nav-item nav-link',
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
            # print((f.decrypt((el.wallet).encode())).decode())
            # print(el.password_words)
            list_wallets[(f.decrypt((el.wallet).encode()).decode())] = el.wallet
        if wallet['wallet'] in list_wallets:
            wallet_address_hash = (list_wallets[wallet['wallet']])
            Wallets.query.filter_by(wallet=wallet_address_hash).delete()
            # commit => save
            db.session.commit()
        return redirect('/wallets')


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'hash_password_words' in session and 'password' in session and 'words' in session:
        elements_nav = [
            'nav-item nav-link',
            'nav-item nav-link',
            'nav-item nav-link active',
            'nav-item nav-link']
        return render_template('wallets.html', elements_nav=elements_nav)
    else:
        return redirect('/authentication')


@app.route('/support', methods=['GET', 'POST'])
def support():
    if 'hash_password_words' in session and 'password' in session and 'words' in session:
        elements_nav = [
            'nav-item nav-link',
            'nav-item nav-link',
            'nav-item nav-link',
            'nav-item nav-link active']
        return render_template('wallets.html', elements_nav=elements_nav)
    else:
        return redirect('/authentication')


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
