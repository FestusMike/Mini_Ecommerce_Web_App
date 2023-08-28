import unittest
from market import app, db, bcrypt
from market.models import User
from market.routes import GenerateOTP
from datetime import datetime, timedelta

class TestGenerateOTP(unittest.TestCase):
    def test_otp_length(self):
        otp = GenerateOTP()
        self.assertEqual(len(otp), 6, "Generated OTP length should be 6")

    def test_otp_characters(self):
        otp = GenerateOTP()
        self.assertTrue(all(c.isdigit() for c in otp), "Generated OTP should contain only digits")

class TestAppRoutes(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://root:Timi1234@localhost/market' #'sqlite:///test.db' 
        self.app = app.test_client()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_register_route(self):
        response = self.app.post('/register', data={
            'username': 'testuser',
            'email_address': 'test@example.com',
            'password1': 'password',
            'password2': 'password'
        }, follow_redirects=True)

        self.assertIn(b'Account Created Successfully', response.data)

    def test_login_route(self):
        user = User(username='testuser', email_address='test@example.com', password_hash=bcrypt.generate_password_hash('password').decode('utf-8'))
        db.session.add(user)
        db.session.commit()

        response = self.app.post('/login', data={
            'username': 'testuser',
            'password': 'password'
        }, follow_redirects=True)

        self.assertIn(b'Success! You are logged in', response.data)

    def test_logout_route(self):
        response = self.app.get('/logout', follow_redirects=True)

        self.assertIn(b'You have logged out', response.data)

    def test_password_reset_otp_route(self):
        response = self.app.post('/getOTP', data={
            'email_address': 'test@example.com'
        }, follow_redirects=True)

        self.assertIn(b'A password reset OTP has been sent', response.data)

    def test_enter_otp_route(self):
        user = User(email_address='test@example.com', token=GenerateOTP(), token_expiration=datetime.now() + timedelta(minutes=10))
        db.session.add(user)
        db.session.commit()

        response = self.app.post('/enterOTP', data={
            'token': user.token
        }, follow_redirects=True)

        self.assertIn(b'Redirecting to /reset_password', response.data)

    def test_reset_password_route(self):
        user = User(email_address='test@example.com', token=GenerateOTP(), token_expiration=datetime.now() + timedelta(minutes=10))
        db.session.add(user)
        db.session.commit()

        response = self.app.post(f'/reset_password?token={user.token}', data={
            'password1': 'newpassword',
            'password2': 'newpassword'
        }, follow_redirects=True)

        self.assertIn(b'Your password has been reset successfully', response.data)

    def test_create_advert_route(self):
        with self.app:
            self.app.post('/login', data={
                'username': 'testuser',
                'password': 'password'
            })

            response = self.app.post('/advert', data={
                'name': 'Test Item',
                'price': 10.99,
                'barcode': '123456',
                'description': 'A test item description'
            }, follow_redirects=True)

            self.assertIn(b'Your advert has been successfully placed', response.data)


if __name__ == '__main__':
    unittest.main()






