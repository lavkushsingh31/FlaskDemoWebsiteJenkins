from flask import Flask, render_template, request, redirect, url_for, session
from flask_oauth import OAuth
import askForConnections
import hashlib
import os



# Google Configs
GOOGLE_CLIENT_ID = '665465619766-u41sjqdbdehlucnl8srhhmar7d9d9fm6.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '_j3fi51pAM-E_258I42Gzvji'
REDIRECT_URI = '/oauth2callback'  # one of the Redirect URIs from Google APIs console

SECRET_KEY = 'development key'
DEBUG = True


FACEBOOK_APP_ID = '265567784103855'
FACEBOOK_APP_SECRET = 'b3fce0e5cc3f8e728aeae0fee0a067b6'


app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)

facebook = oauth.remote_app('facebook',
                            base_url='https://graph.facebook.com/',
                            request_token_url=None,
                            access_token_url='/oauth/access_token',
                            authorize_url='https://www.facebook.com/dialog/oauth',
                            consumer_key=FACEBOOK_APP_ID,
                            consumer_secret=FACEBOOK_APP_SECRET,
                            request_token_params={'scope': 'email'}
)


@app.route('/', methods=['GET', 'POST'])
def landingpage():
    return render_template('landing.html')


@app.route('/register.html', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Fetching data from the form
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        email = userDetails['email']
        passwordHash = hashlib.md5(password.encode())
        print('Original Password: '+password)
        print('Hashed Password: ' + passwordHash.hexdigest())

        try:
            # Ask for connection
            connection = askForConnections.getConnection()
            print("Connection successful!")

            cursor = connection.cursor()

            sql = "Insert into register (Name, Email, Password) " \
                  + " values (%s, %s, %s) "

            # Execute sql, and pass two parameters.
            cursor.execute(sql, (username, email, passwordHash.hexdigest()))

            connection.commit()

            print("Data Insertion Successful")
            return redirect(url_for('registersuccess'))
        finally:
            connection.close()

    return render_template('register.html')


@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print('inside Post')
        if request.form.get('Login') == 'Login':
            userDetails = request.form
            username = userDetails['email']
            password = userDetails['password']
            passwordHash = hashlib.md5(password.encode())
            hashedPasswordtoMatch = passwordHash.hexdigest()
            try:
                # Ask for connection
                connection = askForConnections.getConnection()
                print("Connection successful!")
                cursor = connection.cursor()
                cursor.execute("SELECT Email, Password from register where Email='" + username + "' and Password='" + hashedPasswordtoMatch + "'")
                data = cursor.fetchone()
                if data is None:
                    return "Wrong Credentails"
                else:
                    return redirect(url_for('welcome'))
            finally:
                connection.close()
        print('Before google login')
        if request.form.get('GoogleLogin') == 'GoogleLogin':
            print('Inside Elif')
            access_token = session.get('access_token')
            if access_token is None:
                return redirect(url_for('glogin'))

            access_token = access_token[0]
            from urllib.request import Request, urlopen
            from urllib.error import URLError

            headers = {'Authorization': 'OAuth ' + access_token}
            req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                          None, headers)
            try:
                res = urlopen(req)
            except URLError as e:
                if e.code == 401:
                    # Unauthorized - bad token
                    session.pop('access_token', None)
                    return redirect(url_for('glogin'))
                return res.read()
            return res.read()
        if request.form.get('FacebookLogin') == 'FacebookLogin':
            print('Inside Facebook Login')
            return redirect(url_for('flogin'))

    return render_template('login.html')


@app.route('/welcome')
def welcome():
    return render_template('Welcome.html')


@app.route('/registersuccess')
def registersuccess():
    return render_template('registersuccess.html')


@app.route('/flogin')
def flogin():
    return facebook.authorize(callback=url_for('facebook_authorized',
                                               next=request.args.get('next') or request.referrer or None,
                                               external=True))


@app.route('/flogin/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['oauth_token'] = (resp['access_token'], '')
    me = facebook.get('/me')
    return 'Logged in as id=%s name=%s redirect=%s' % \
        (me.data['id'], me.data['name'], request.args.get('next'))


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')


@app.route('/glogin')
def glogin():
    callback = url_for('authorized', _external=True)
    return google.authorize(callback=callback)


@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('welcome'))


@google.tokengetter
def get_access_token():
    return session.get('access_token')


if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')
