from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file
from flask_login import login_user, current_user, logout_user, login_required
from extensions import db, bcrypt, login_manager, migrate
from models import User, Food
import pyotp
import qrcode
import io
import re

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'supersecretkey'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///calorie_counter.db'

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    
    login_manager.login_view = 'login'
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "danger"

    with app.app_context():
        db.create_all()

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            check = password_check(password)
            if not check['password_ok']:
                flash('Password is too weak. Please choose a stronger one.', 'danger')
                return redirect(url_for('register'))

            user = User.query.filter_by(username=username).first()
            if user:
                flash('Username already exists. Please choose a different one.', 'danger')
                return redirect(url_for('register'))
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, password=hashed_password)
            user.tfa_secret = pyotp.random_base32()
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('qr_code', user_id=user.id))
        return render_template('register.html')

    @app.route('/')
    def index():
        return redirect(url_for('login'))

    @app.route('/qr_code/<int:user_id>')
    def qr_code(user_id):
        user = User.query.get_or_404(user_id)
        return render_template('qr_code.html', user=user)

    @app.route('/qr_code_image/<int:user_id>')
    def qr_code_image(user_id):
        user = User.query.get_or_404(user_id)
        url = pyotp.totp.TOTP(user.tfa_secret).provisioning_uri(user.username, issuer_name="CalorieCounter")
        qr = qrcode.make(url)
        buf = io.BytesIO()
        qr.save(buf)
        buf.seek(0)
        return send_file(buf, mimetype='image/png')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                session['pre_2fa_userid'] = user.id
                session['next_url'] = request.args.get('next')  # Store the next URL in the session
                return redirect(url_for('two_factor'))
            else:
                flash('Login unsuccessful. Please check username and password', 'danger')
        return render_template('login.html')

    @app.route('/two_factor', methods=['GET', 'POST'])
    def two_factor():
        if 'pre_2fa_userid' not in session:
            return redirect(url_for('login'))
        
        user = User.query.get(session['pre_2fa_userid'])
        if request.method == 'POST':
            token = request.form['token']
            totp = pyotp.TOTP(user.tfa_secret)
            if totp.verify(token):
                login_user(user)
                session.pop('pre_2fa_userid', None)
                next_url = session.pop('next_url', None)  # Get the next URL from the session
                return redirect(next_url or url_for('home'))  # Redirect to the next URL or home page
            else:
                flash('Invalid 2FA token', 'danger')
        
        return render_template('two_factor.html', user=user)

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/home')
    @login_required
    def home():
        last_bmr = session.get('last_bmr', None)
        foods = Food.query.filter_by(user_id=current_user.id).all()
        total_calories = sum(item.calories for item in foods)
        return render_template('home.html', last_bmr=last_bmr, total_calories=total_calories)

    @app.route('/calorie_counter', methods=['GET', 'POST'])
    @login_required
    def calorie_counter():
        if request.method == 'POST':
            food = request.form['food']
            calories = request.form['calories']
            if not calories.isdigit() or int(calories) < 0:
                flash('Calories must be a positive number.', 'danger')
                return redirect(url_for('calorie_counter'))

            new_food = Food(name=food, calories=int(calories), user_id=current_user.id)
            db.session.add(new_food)
            db.session.commit()
            flash('Food item added successfully!', 'success')
            return redirect(url_for('calorie_counter'))
        
        foods = Food.query.filter_by(user_id=current_user.id).all()
        total_calories = sum(item.calories for item in foods)
        return render_template('calorie_counter.html', foods=foods, total_calories=total_calories)

    @app.route('/clear_calories', methods=['POST'])
    @login_required
    def clear_calories():
        Food.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        flash('All calorie data cleared successfully!', 'success')
        return redirect(url_for('calorie_counter'))

    @app.route('/delete/<int:food_id>')
    @login_required
    def delete(food_id):
        food = Food.query.get_or_404(food_id)
        if food.author != current_user:
            abort(403)
        db.session.delete(food)
        db.session.commit()
        flash('Food item has been deleted!', 'success')
        return redirect(url_for('calorie_counter'))

    @app.route('/bmr_calculator', methods=['GET', 'POST'])
    @login_required
    def bmr_calculator():
        bmr = None
        if request.method == 'POST':
            age = int(request.form['age'])
            gender = request.form['gender']
            weight = float(request.form['weight'])
            height = float(request.form['height'])

            if gender == 'male':
                bmr = 88.362 + (13.397 * weight) + (4.799 * height) - (5.677 * age)
            elif gender == 'female':
                bmr = 447.593 + (9.247 * weight) + (3.098 * height) - (4.330 * age)

            session['last_bmr'] = bmr  # Store the last BMR in the session
            flash(f'Your BMR is {bmr:.2f} calories/day', 'success')

        return render_template('bmr_calculator.html', bmr=bmr)

    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def profile():
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'update_password':
                session['current_password'] = request.form['current_password']
                session['new_password'] = request.form['new_password']
                check = password_check(session['new_password'])
                if not check['password_ok']:
                    flash('Password is too weak. Please choose a stronger one.', 'danger')
                    return redirect(url_for('profile'))

                return redirect(url_for('profile_2fa'))
            elif action == 'clear_data':
                Food.query.filter_by(user_id=current_user.id).delete()
                session.pop('last_bmr', None)
                db.session.commit()
                flash('All data cleared successfully!', 'success')

        return render_template('profile.html')

    @app.route('/profile_2fa', methods=['GET', 'POST'])
    @login_required
    def profile_2fa():
        if request.method == 'POST':
            token = request.form['token']
            totp = pyotp.TOTP(current_user.tfa_secret)
            if totp.verify(token):
                hashed_password = bcrypt.generate_password_hash(session['new_password']).decode('utf-8')
                current_user.password = hashed_password
                db.session.commit()
                session.pop('current_password', None)
                session.pop('new_password', None)
                flash('Password updated successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Invalid 2FA token', 'danger')

        return render_template('profile_2fa.html')

    @app.route('/confirm_delete_account', methods=['GET', 'POST'])
    @login_required
    def confirm_delete_account():
        if request.method == 'POST':
            password = request.form['password']
            token = request.form['token']

            if bcrypt.check_password_hash(current_user.password, password):
                totp = pyotp.TOTP(current_user.tfa_secret)
                if totp.verify(token):
                    Food.query.filter_by(user_id=current_user.id).delete()
                    db.session.delete(current_user)
                    db.session.commit()
                    session.pop('last_bmr', None)
                    
                    flash('Your account has been deleted successfully!', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Invalid 2FA token', 'danger')
            else:
                flash('Incorrect password.', 'danger')
        
        return render_template('confirm_delete_account.html')

    return app

def password_check(password):
    """
    Verifies the strength of the password
    Returns dict with wrong criteria
    Minimum for a strong password:
    8 chars length, 1 digit, 1 upper, 1 lower
    """

    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None

    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error)

    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
    }


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
