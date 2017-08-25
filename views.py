from __future__ import print_function
import flask
from flask import Flask
from init import app
import models
from init import db
import sys
import bcrypt
import os
import base64
import random
import string
from flask import abort
from flask import request
from settings import st_secret_key
from settings import st_publish_key
import stripe
from stripe import Customer
from stripe import Charge
from stripe import api_key
from random import choice
from string import ascii_uppercase

@app.before_request
def setup_csrf():
    # make a cross-site request forgery preventing token
    if 'csrf_token' not in flask.session:
        flask.session['csrf_token'] = base64.b64encode(os.urandom(32)).decode('ascii')


@app.before_request
def setup_user():
    """
    Figure out if we have an authorized user, and look them up.
    This runs for every request, so we don't have to duplicate code.
    """
    if 'auth_user' in flask.session:
        user = models.User.query.get(flask.session['auth_user'])
        # save the user in `flask.g`, which is a set of globals for this request
        flask.g.user = user

stripe_keys = {
  'secret_key': st_secret_key,
  'publishable_key': st_publish_key
}

stripe.api_key = stripe_keys['secret_key']


@app.route('/')
def supertheatre():
    prime = models.Movie.query.filter_by(category = 'prime')
    primecount = (5 - (prime.count() % 5))
    if primecount == 5: primecount = 0
    dollar = models.Movie.query.filter_by(category = 'dollar')
    dollarcount = (5 - (dollar.count() % 5))
    if dollarcount == 5: dollarcount = 0
    foreign = models.Movie.query.filter_by(category = 'foreign')
    foreigncount = (5 - (foreign.count() % 5))
    if foreigncount == 5: foreigncount = 0
    return flask.render_template('index.html', prime = prime, foreign = foreign, dollar = dollar, dollarcount = dollarcount, primecount = primecount, foreigncount = foreigncount)

@app.route('/<title>/')
def moviepage(title):
    movie = models.Movie.query.filter_by(title = title).first()
    if movie is None:
        abort(404)
    elif movie.category == "dollar":
        amount = 100
    else:
        amount = 800

    if 'prime' == movie.category or 'dollar' == movie.category or 'foreign' == movie.category:
        if 'auth_user' in flask.session:
            return flask.render_template('movie-name.html',movie = movie,key = stripe_keys['publishable_key'], amount = amount, state = 'logged_in')
        else:
            return flask.render_template('movie-name.html',movie = movie,key = stripe_keys['publishable_key'], amount=amount)
    else:
        return flask.redirect(flask.url_for('comingsoonpage'))

@app.route('/comingsoon')
def comingsoonpage():
    oneweek = models.Movie.query.filter_by(category = '1week')
    twoweek = models.Movie.query.filter_by(category = '2week')
    threeweek = models.Movie.query.filter_by(category = '3week')
    return flask.render_template('comingsoon.html', oneweek = oneweek, twoweek = twoweek, threeweek = threeweek )

@app.route('/login-createaccount')
def loginpage():
    if 'auth_user' in flask.session:
        return flask.redirect(flask.url_for('manageaccountpage'))
    return flask.render_template('login-createaccount.html')

@app.route('/login/<link>/',  methods=['POST'])
def handlelogin(link):
    if flask.request.form['submit'] == 'Retreive':
        email = flask.request.form['retreival']
        user = models.User.query.filter_by(email=email).first()
        if user is not None:
            print('email_sent', file=sys.stderr)
            return flask.render_template('login-createaccount.html', state='email_sent')
        else:
            print('wrong_email', file=sys.stderr)
            return flask.render_template('login-createaccount.html', state='wrong_email')

    # POST request to /login - check user
    username = flask.request.form['username']
    password = flask.request.form['password']
    # try to find user
    if (loginvaidation(username,password)):
        return flask.redirect(flask.url_for('supertheatre'))
    else:
        return flask.render_template('login-createaccount.html', state='bad_login')

def loginvaidation(username,password):
    user = models.User.query.filter_by(username=username).first()
    if user is None:
        user = models.User.query.filter_by(email=username).first()
    if user is not None:
        # hash the password the user gave us
        # for verifying, we use their real hash as the salt
        pw_hash = bcrypt.hashpw(password.encode('utf8'), user.pw_hash)
        # is it good?
        if pw_hash == user.pw_hash:
            # yay!
            flask.session['auth_user'] = user.id
            # And redirect to page, since this is a successful POST
            return True

    # if we got this far, either username or password is no good
    # For an error in POST, we'll just re-show the form with an error message
    return False

@app.route('/create_user/', methods=['POST'])
def create_user():
    login = flask.request.form['createusername']
    password = flask.request.form['createpassword']
    email = flask.request.form['email']
    print('got this far', file=sys.stderr)
    if login is None or password is None or email is None:
        return flask.render_template('login-createaccount.html', state='empty')
    if len(login) == 0 or len(password) == 0 or len(email) == 0:
        return flask.render_template('login-createaccount.html', state='empty')
    print('got this far2', file=sys.stderr)
    # do the passwords match?
    if password != flask.request.form['Createpasswordcheck']:
        return flask.render_template('login-createaccount.html', state='password-mismatch')
    # is the login ok?
    if len(login) > 20:
        return flask.render_template('login-createaccount.html', state='bad-username')
    # search for existing user
    existing = models.User.query.filter_by(username=login).first()
    if existing is not None:
        # oops
        return flask.render_template('login-createaccount.html', state='username-used')
    print('got this far3', file=sys.stderr)
    # create user
    user = models.User()
    user.username = login
    # hash password
    user.pw_hash = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt(15))
    # save email
    user.email = email
    # save user
    user.identify = "blah"
    db.session.add(user)
    db.session.commit()

    flask.session['auth_user'] = user.id

    return flask.redirect(flask.url_for('supertheatre'))#(flask.request.form['url'], 303)

@app.route('/logout', methods=['post'])
def handle_logout():
    # user wants to say goodbye, just forget about them
    del flask.session['auth_user']
    # redirect to specfied source URL, or / if none is present
    return flask.redirect(flask.url_for('supertheatre'))

@app.route('/handlequicklogin/<title>/', methods=['POST'])
def handle_quicklogin(title):
    print("got here", file=sys.stderr)
    print(flask.request.form['submit'], file=sys.stderr)

    if flask.request.form['submit'] == 'Submit':
        key = accessverification(title)
        return flask.redirect(flask.url_for('movie', title=title, key=key))
    if flask.request.form['submit'] == 'Login':
        username = flask.request.form['username']
        password = flask.request.form['password']
        if loginvaidation(username,password):
            #function to charge existing user.
            return flask.redirect(flask.url_for('movie', title=title, key=key))
        else:
            return flask.render_template('login-createaccount.html', state='bad_login')

    elif flask.request.form['submit'] == 'Create Account':
        return flask.redirect(flask.url_for('loginpage'))

    return flask.redirect(flask.url_for('supertheatre'))

@app.route('/manageaccount')
def manageaccountpage():
    if 'auth_user' not in flask.session:
        return flask.redirect(flask.url_for('loginpage'))

    return flask.render_template('manageaccount.html')

@app.route('/manageaccount', methods=['post'])
def handle_manageaccount():
    return flask.redirect(flask.url_for('supertheatre'))

@app.route('/update_email', methods=['post'])
def update_email():
    new = flask.request.form['newemail']
    verify = flask.request.form['password']

    pw_hash = bcrypt.hashpw(verify.encode('utf8'), flask.g.user.pw_hash)
    if pw_hash == flask.g.user.pw_hash:
        flask.g.user.email = new
        db.session.commit()
        return flask.redirect(flask.url_for('supertheatre'))
    return flask.redirect(flask.url_for('supertheatre'))

@app.route('/update_username', methods=['post'])
def update_username():
    new = flask.request.form['newusername']
    verify = flask.request.form['password']

    pw_hash = bcrypt.hashpw(verify.encode('utf8'), flask.g.user.pw_hash)
    if pw_hash == flask.g.user.pw_hash:
        flask.g.user.username = new
        db.session.commit()
        return flask.redirect(flask.url_for('supertheatre'))
    return flask.redirect(flask.url_for('supertheatre'))

@app.route('/update_password', methods=['post'])
def update_password():
    new = flask.request.form['newpassword']
    verify = flask.request.form['password']
    confirm = flask.request.form['confirm']

    pw_hash = bcrypt.hashpw(verify.encode('utf8'), flask.g.user.pw_hash)
    if pw_hash == flask.g.user.pw_hash:
        if new == confirm:
            print('got this far', file=sys.stderr)
            new_pw_hash = bcrypt.hashpw(new.encode('utf8'), bcrypt.gensalt(15))
            flask.g.user.pw_hash = new_pw_hash
            db.session.commit()
            return flask.redirect(flask.url_for('supertheatre'))
    return flask.redirect(flask.url_for('supertheatre'))

@app.route('/delete', methods=['post'])
def delete_user():
    user = flask.g.user
    # user wants to say goodbye, just forget about them
    del flask.session['auth_user']
    # redirect to specfied source URL, or / if none is present
    models.User.query.filter_by(id=user.id).delete()
    db.session.commit()
    return flask.redirect(flask.url_for('supertheatre'))

def accessverification(title):
    print("generating key", file=sys.stderr)
    key = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + string.whitespace) for _ in range(30))
    flask.session[key] = title
    print("key is gonna work  " + key, file=sys.stderr)
    return key

@app.route('/ticket/<title>/<key>')
def movie(title,key):
    print("at movie", file=sys.stderr)
    if key not in flask.session:
        print("fail", file=sys.stderr)
        return flask.redirect(flask.url_for('supertheatre'))        #will be a 404.
    del flask.session[key]
    print("pass", file=sys.stderr)
    return flask.render_template('movie.html', title = title)


def charge_customer():

    return

@app.route('/test-stripe/<movie>/<int:amount>/', methods=['post'])
def handle_charge(movie,amount):
    try:
        # Use Stripe's library to make requests...
        # Amount in cents
        amount = amount
        token= request.form['stripeToken']
        stripe.api_key = stripe_keys['secret_key']

        customer = Customer.create(
            email=request.form['stripeEmail'],
            source=token
        )

        charge = Charge.create(
            customer=customer.id,
            amount=amount,
            currency='usd',
            description=movie
        )
        key = accessverification(movie)
        return flask.redirect(flask.url_for('movie', title = movie, key=key))
       # pass
    except stripe.error.CardError as e:
          # Since it's a decline, stripe.error.CardError will be caught
          body = e.json_body
          err  = body['error']
          print("Status is: %s" % e.http_status, file=sys.stderr)
          #print "Status is: %s" % e.http_status

          print("Type is: %s"  % err['type'], file=sys.stderr)
          #print "Type is: %s" % err['type']

          print("Code is: %s" % err['code'], file=sys.stderr)
          #print "Code is: %s" % err['code']

          # param is '' in this case
          #print("Param is: %s" % err['param'], file=sys.stderr)
          #print "Param is: %s" % err['param']

          print("Message is: %s" % err['message'], file=sys.stderr)
          #print "Message is: %s" % err['message']

          return flask.redirect(flask.url_for('supertheatre'))
    except stripe.error.RateLimitError as e:
          # Too many requests made to the API too quickly
          return flask.redirect(flask.url_for('supertheatre'))
    except stripe.error.InvalidRequestError as e:
          # Invalid parameters were supplied to Stripe's API
          return flask.redirect(flask.url_for('supertheatre'))
    except stripe.error.AuthenticationError as e:
          # Authentication with Stripe's API failed
          # (maybe you changed API keys recently)
          return flask.redirect(flask.url_for('supertheatre'))
    except stripe.error.APIConnectionError as e:
          # Network communication with Stripe failed
          return flask.redirect(flask.url_for('supertheatre'))
    except stripe.error.StripeError as e:
          # Display a very generic error to the user, and maybe send
          # yourself an email
          return flask.redirect(flask.url_for('supertheatre'))
    except Exception as e:
          # Something else happened, completely unrelated to Stripe
          return flask.redirect(flask.url_for('supertheatre'))



@app.errorhandler(404)
def pageNotFound(e):
    return flask.render_template('404.html', request=flask.request), 404

@app.errorhandler(500)
def servererror(e):
    return flask.render_template('500.html', request=flask.request), 500

@app.route('/hw/')
def delete_me():
    return flask.render_template('hw.html')