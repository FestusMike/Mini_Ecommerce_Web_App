from flask import render_template, redirect, url_for, flash, request
from market import app, bcrypt, db, mail
from market.models import Item, User
from market.forms import RegisterForm, LoginForm, PurchaseItemform, SellItemform, ResetPassword, EnterOTP, NewPassword, CreateAdvert
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from datetime import datetime, timedelta
import random, string

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
                msg = Message(
                    subject="Thanks For Joining Us",
                    sender='noreply@ecommerce.com',
                    recipients=[user_to_create.email_address]
                )
                msg.html = f"""Hello {user_to_create.username}, <p>We are happy to welcome you aboard. We wish you a happy shopping spree.
                             Kindly note that this is a virtually generated e-mail address and we can\'t be contacted through this medium. To message us, send us
                             an email on festusmike30@yahoo.com. Thank You.</p>"""
                mail.send(msg)
            except Exception as e:
                app.logger.error(f"Error sending email to {user_to_create.email_address}: {str(e)}")
                flash("An error occurred while sending the welcome email. Please contact support.", category='danger')

            login_user(user_to_create)
            flash(f'Account Created Successfully, You are now logged in as: {user_to_create.username}. Enjoy your Shopping Spree', category='success')
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
            try:
                token = GenerateOTP()
                token_expiration = datetime.now() + timedelta(minutes=10)
                user.token = token
                user.token_expiration = token_expiration
                db.session.commit()

                otp_msg = Message(
                    subject="Password Reset Token",
                    sender='noreply@fakeshoprite.com',
                    recipients=[user.email_address]
                )
                otp_msg.html = f"""<p>Your Password Reset OTP is {user.token}.</p>"""

                # Send the email
                mail.send(otp_msg)
            except Exception as e:
            
                app.logger.error(f"Error sending OTP email to {user.email_address}: {str(e)}")
                flash("An error occurred while sending the OTP email. Please contact support.", category='danger')

            flash(f'A password reset OTP has been sent to {user.email_address}. Kindly check your inbox or spam folder.', category='info')
            return redirect(url_for('enter_otp'))
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
            try:
                item_to_create = Item(
                    name=form.name.data,
                    price=form.price.data,
                    barcode=form.barcode.data,
                    description=form.description.data
                )
                item_to_create.create(current_user)
                db.session.add(item_to_create)
                db.session.commit()

                msg = Message(
                    subject="Notice of Advert Placement",
                    sender='noreply@ecommerce.com',
                    recipients=[current_user.email_address]
                )
                msg.html = f"""<p>Hello {current_user.username}, Congratulations, Your Advert has been Successfully Placed on the Market. Please be informed that your commodity might be taken down if any fraudulent activity is discovered.
                        Kindly note that this is a virtually generated e-mail address and we can't be contacted through this medium. To message us, send us
                        an email on festusmike30@yahoo.com. Thank You.</p>"""

                # Send the email
                mail.send(msg)
            except Exception as e:
                
                app.logger.error(f"Error sending advert placement email to {current_user.email_address}: {str(e)}")
                flash("An error occurred while sending the advert placement email. Please contact support.", category='danger')

            flash('Your advert has been successfully placed.', category='success')
            return redirect(url_for('market_page'))

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

