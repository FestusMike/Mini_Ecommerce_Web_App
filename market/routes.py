from flask import render_template, redirect, url_for, flash, request
from market import app, bcrypt, db
from market.models import Item, User
from market.forms import RegisterForm, LoginForm, PurchaseItemform, SellItemform, ResetPassword, EnterOTP, NewPassword, CreateAdvert
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import random, string
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException  
import os


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        email = User.query.filter_by(email_address=form.email_address.data).first()

        if user and email:
            flash('The provided username and e-mail address already exist in our database', category='danger')
        elif user:
            flash(f'User with the username {user.username} already exists. Try another username.', category='danger')
        elif email:
            flash('User with the same email already exists', category='danger')
        else:
            user_to_create = User(
                username=form.username.data,
                email_address=form.email_address.data,
                password_hash=bcrypt.generate_password_hash(form.password1.data).decode('utf-8')
            ) 

            db.session.add(user_to_create)
            db.session.commit()

            try:
                # Set up Sendinblue API configuration
                configuration = sib_api_v3_sdk.Configuration()
                configuration.api_key['api-key'] = os.environ.get('EMAIL_API_KEY')

                # Create an instance of the Sendinblue TransactionalEmailsApi
                api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

                # Define email parameters
                subject = "Welcome to Mini Market!"
                sender = {"name" : 'Mini Market', "email": os.environ.get('EMAIL_SENDER')}
                reply_to = {"email": os.environ.get('EMAIL_REPLY_TO')}
                html_content = f"<html><body><h1>Welcome, {user_to_create.username}!</h1> <p>We are happy to have you here. Welcome Aboard! </p></body></html>"
                to = [{"email": user_to_create.email_address, "name": user_to_create.username}]

                # Create an instance of SendSmtpEmail
                send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, reply_to=reply_to, html_content=html_content, sender=sender, subject=subject)

                # Send the transactional email
                api_response = api_instance.send_transac_email(send_smtp_email)
                print(api_response)

            except ApiException as e:
                    print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)

            login_user(user_to_create)
            flash(f'Account Created Successfully, You are now logged in as: {user_to_create.username}. Enjoy your Shopping Spree. Meanwhile, a welcome message has been sent to {user_to_create.email_address}.', category='success')
            return redirect(url_for('market_page'))

    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'{err_msg}', category='danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and bcrypt.check_password_hash(attempted_user.password_hash, form.password.data):
            login_user(attempted_user)
            flash(f'Success! You are logged in as: {attempted_user.username}', category='success')
            return redirect(url_for('market_page'))
        else:
            flash('Username and Password do not match! Please Try Again', category='danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have logged out!', category='info')
    return redirect(url_for('home'))

 #OTP Generator
def GenerateOTP():
    otp_length = 6
    otp_char = string.digits
    otp = "".join(random.choice(otp_char) for i in range(otp_length))
    return otp

#Getting Your OTP by submitting your registered email
@app.route('/getOTP', methods=['GET', 'POST'])
def password_reset_otp():
    form = ResetPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email_address=form.email_address.data).first()
        if user:
                token = GenerateOTP()
                token_expiration = datetime.now() + timedelta(minutes=5)
                user.token = token
                user.token_expiration = token_expiration
                db.session.commit()
                try:
                    # Set up Sendinblue API configuration
                    configuration = sib_api_v3_sdk.Configuration()
                    configuration.api_key['api-key'] = os.environ.get('EMAIL_API_KEY')
                    # Create an instance of the Sendinblue TransactionalEmailsApi
                    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
                    # Define email parameters
                    subject = "Password Reset Token!"
                    sender = {"name" : 'Mini Market', "email": os.environ.get('EMAIL_SENDER')}
                    reply_to = {"email": os.environ.get('EMAIL_REPLY_TO')}
                    html_content = f"""<html><body><h1>Hi {user.username},</h1> <p>Your Password Reset token is {user.token}. Kindly note that it expires after 5 minutes. If you didn't initiate this action, 
                    please ignore this message. </p>
                    <p> Micheal, From Mini Market </p>
                    </body></html>"""
                    to = [{"email": user.email_address, "name": user.username}]
                    #   Create an instance of SendSmtpEmail
                    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, reply_to=reply_to, html_content=html_content, sender=sender, subject=subject)
                    # Send the transactional email
                    api_response = api_instance.send_transac_email(send_smtp_email)
                    print(api_response)
                    flash(f'A password reset OTP has been sent to {user.email_address}. Kindly check your inbox or spam folder.', category='info')
                    return redirect(url_for('enter_otp'))
                except ApiException as e:
                    print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)
        else:
            flash('No record of your e-mail address in our database. Kindly register with us.', category='danger')
            return redirect(url_for('register'))

    return render_template('get_otp.html', form=form)


#Entering the OTP sent to your email
@app.route('/enterOTP', methods=['GET', 'POST'])
def enter_otp():
    form = EnterOTP()
    if form.validate_on_submit():
        user = User.query.filter_by(token=form.token.data).first()
        if user and user.token_expiration > datetime.now():
            return redirect(f'/reset_password?token={user.token}')
        else:
            flash('Invalid or Expired OTP', category='danger')
            return redirect(url_for('password_reset_otp'))
    return render_template('enter_otp.html', form=form)


#This function checks for the otp and sets the table in preparation for a new password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')  # Retrieve the token from the query parameters
    user = User.query.filter_by(token=token).first()  # Find the user by token
    if not user or user.token_expiration < datetime.now():
        flash('Invalid or Expired Token', category='danger')
        return redirect(url_for('password_reset_otp'))

    form = NewPassword()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password1.data).decode('utf-8')
        user.password_hash = hashed_password
        user.token = None
        user.token_expiration = None
        db.session.commit()

        flash('Your password has been reset successfully', category='success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)

#This function creates a new advert

@app.route('/advert', methods=['GET', 'POST'])
@login_required
def create_advert():
    form = CreateAdvert()

    if form.validate_on_submit():
        barcode_check = Item.query.filter_by(barcode=form.barcode.data).first()

        if barcode_check:
            flash(f'An item with the barcode {barcode_check.barcode} already exists. Kindly re-confirm the barcode.', category='danger')
        else:
                item_to_create = Item(
                    name=form.name.data,
                    price=form.price.data,
                    barcode=form.barcode.data,
                    description=form.description.data
                )
                item_to_create.create(current_user)
                db.session.add(item_to_create)
                db.session.commit()

                try:
                    # Set up Sendinblue API configuration
                    configuration = sib_api_v3_sdk.Configuration()
                    configuration.api_key['api-key'] = os.environ.get('EMAIL_API_KEY')
                    # Create an instance of the Sendinblue TransactionalEmailsApi
                    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
                    # Define email parameters
                    subject = "Notice of Advert Placement!"
                    sender = {"name" : 'Mini Market', "email": os.environ.get('EMAIL_SENDER')}
                    reply_to = {"email": os.environ.get('EMAIL_REPLY_TO')}
                    html_content =  f"""<h2>Hello {current_user.username},</h2> <p> Congratulations, Your Advert has been Successfully Placed on the Market. 
                    Please be informed that your commodity might be taken down if any fraudulent activity is discovered.
                    To contact us, send us an email on festusmike98@gmail.com. Thank You.</p>"""
                    to = [{"email": current_user.email_address, "name": current_user.username}]
                    #   Create an instance of SendSmtpEmail
                    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, reply_to=reply_to, html_content=html_content, sender=sender, subject=subject)
                    # Send the transactional email
                    api_response = api_instance.send_transac_email(send_smtp_email)
                    print(api_response)
                    flash('Your advert has been successfully placed.', category='success')
                    return redirect(url_for('market_page'))
                except ApiException as e:
                    print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)
    return render_template('create_advert.html', form=form)

@app.route('/market', methods=['GET', 'POST'])
@login_required
def market_page():
    purchase_form = PurchaseItemform()
    selling_form = SellItemform()
    if request.method == 'POST':
        #Buy Item Logic
        purchased_item = request.form.get('purchased_item')
        p_item_object = Item.query.filter_by(name=purchased_item).first()
        if p_item_object:
            if current_user.can_purchase(p_item_object):
                p_item_object.buy(current_user)
                flash(f'Congratulations, You purchased {p_item_object.name} for {p_item_object.price}', category='success')
            else:
                flash(f'Unfortunately, you don\'t have enough money to purchase {p_item_object.name} for {p_item_object.price}', category='danger')
        #Sell item Logic
        sold_item = request.form.get('sold_item')
        s_item_object = Item.query.filter_by(name=sold_item).first()
        
        if s_item_object:
            if current_user.can_sell(s_item_object):
                s_item_object.sell(current_user)
                flash(f'Congratulations, You sold {s_item_object.name} to the market', category='success')
            else:
                flash(f'oops! Something went wrong with selling {s_item_object.name}', category='danger')
        return redirect(url_for('market_page'))
 
    if request.method == 'GET':
        items = Item.query.filter_by(owner=None)
        owned_items = Item.query.filter_by(owner=current_user.id)
    return render_template('market.html', items=items, purchase_form=purchase_form, owned_items=owned_items, selling_form=selling_form)

