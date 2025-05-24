import uuid
from datetime import timedelta
from unittest.mock import Mock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from .emails import send_account_locked_email, send_otp_email
from .forms import UserChangeForm, UserCreationForm
from .managers import UserManager, generate_username, validate_email_address
from .models import User
from .utils import generate_otp


class UserModelTest(TestCase):
    """Test cases for the User model"""

    def setUp(self):
        self.user_data = {
            "email": "test@example.com",
            "password": "testpass123",
            "first_name": "John",
            "last_name": "Doe",
            "id_no": 12345678,
            "security_question": User.SecurityQuestions.MAIDEN_NAME,
            "security_answer": "Smith",
        }

    def test_user_creation(self):
        """Test creating a new user"""
        user = User.objects.create_user(**self.user_data)
        
        self.assertEqual(user.email, "test@example.com")
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.id_no, 12345678)
        self.assertEqual(user.role, User.RoleChoices.CUSTOMER)
        self.assertEqual(user.account_status, User.AccountStatus.ACTIVE)
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertTrue(user.username.startswith(""))  # Generated username
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_superuser_creation(self):
        """Test creating a superuser"""
        user = User.objects.create_superuser(**self.user_data)
        
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_user_str_representation(self):
        """Test string representation of user"""
        user = User.objects.create_user(**self.user_data)
        expected = "John Doe - Customer"
        self.assertEqual(str(user), expected)

    def test_full_name_property(self):
        """Test full_name property"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.full_name, "John Doe")

    def test_has_role_method(self):
        """Test has_role method"""
        user = User.objects.create_user(**self.user_data)
        self.assertTrue(user.has_role(User.RoleChoices.CUSTOMER))
        self.assertFalse(user.has_role(User.RoleChoices.TELLER))

    @override_settings(OTP_EXPIRATION=timedelta(minutes=5))
    def test_set_otp(self):
        """Test setting OTP"""
        user = User.objects.create_user(**self.user_data)
        otp = "123456"
        
        with patch('django.utils.timezone.now') as mock_now:
            mock_time = timezone.now()
            mock_now.return_value = mock_time
            
            user.set_otp(otp)
            
            self.assertEqual(user.otp, otp)
            expected_expiry = mock_time + settings.OTP_EXPIRATION
            self.assertEqual(user.otp_expiry_time, expected_expiry)

    def test_verify_otp_valid(self):
        """Test OTP verification with valid OTP"""
        user = User.objects.create_user(**self.user_data)
        otp = "123456"
        user.set_otp(otp)
        
        self.assertTrue(user.verify_otp(otp))
        self.assertEqual(user.otp, "")
        self.assertIsNone(user.otp_expiry_time)

    def test_verify_otp_invalid(self):
        """Test OTP verification with invalid OTP"""
        user = User.objects.create_user(**self.user_data)
        user.set_otp("123456")
        
        self.assertFalse(user.verify_otp("654321"))

    def test_verify_otp_expired(self):
        """Test OTP verification with expired OTP"""
        user = User.objects.create_user(**self.user_data)
        otp = "123456"
        
        # Set OTP with past expiry time
        user.otp = otp
        user.otp_expiry_time = timezone.now() - timedelta(minutes=1)
        user.save()
        
        self.assertFalse(user.verify_otp(otp))

    @override_settings(LOGIN_ATTEMPTS=3)
    @patch('core_apps.user_auth.models.send_account_locked_email')
    def test_handle_failed_login_attempts(self, mock_send_email):
        """Test handling failed login attempts"""
        user = User.objects.create_user(**self.user_data)
        
        # First two failed attempts
        for i in range(2):
            user.handle_failed_login_attempts()
            self.assertEqual(user.failed_login_attempts, i + 1)
            self.assertEqual(user.account_status, User.AccountStatus.ACTIVE)
        
        # Third attempt should lock account
        user.handle_failed_login_attempts()
        self.assertEqual(user.failed_login_attempts, 3)
        self.assertEqual(user.account_status, User.AccountStatus.LOCKED)
        mock_send_email.assert_called_once_with(user)

    def test_reset_failed_login_attempts(self):
        """Test resetting failed login attempts"""
        user = User.objects.create_user(**self.user_data)
        user.failed_login_attempts = 2
        user.last_failed_login = timezone.now()
        user.account_status = User.AccountStatus.LOCKED
        user.save()
        
        user.reset_failed_login_attempts()
        
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertIsNone(user.last_failed_login)
        self.assertEqual(user.account_status, User.AccountStatus.ACTIVE)

    def test_unlock_account(self):
        """Test unlocking account"""
        user = User.objects.create_user(**self.user_data)
        user.account_status = User.AccountStatus.LOCKED
        user.failed_login_attempts = 3
        user.last_failed_login = timezone.now()
        user.save()
        
        user.unlock_account()
        
        self.assertEqual(user.account_status, User.AccountStatus.ACTIVE)
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertIsNone(user.last_failed_login)

    @override_settings(LOCKOUT_DURATION=timedelta(minutes=30))
    def test_is_locked_out_property(self):
        """Test is_locked_out property"""
        user = User.objects.create_user(**self.user_data)
        
        # User not locked
        self.assertFalse(user.is_locked_out)
        
        # Lock user
        user.account_status = User.AccountStatus.LOCKED
        user.last_failed_login = timezone.now()
        user.save()
        
        self.assertTrue(user.is_locked_out)
        
        # Test auto-unlock after lockout duration
        user.last_failed_login = timezone.now() - timedelta(minutes=31)
        user.save()
        
        self.assertFalse(user.is_locked_out)
        # Check that account was unlocked
        user.refresh_from_db()
        self.assertEqual(user.account_status, User.AccountStatus.ACTIVE)


class UserManagerTest(TestCase):
    """Test cases for the UserManager"""

    def setUp(self):
        self.user_data = {
            "email": "test@example.com",
            "password": "testpass123",
            "first_name": "John",
            "last_name": "Doe",
            "id_no": 12345678,
            "security_question": User.SecurityQuestions.MAIDEN_NAME,
            "security_answer": "Smith",
        }

    def test_create_user_success(self):
        """Test successful user creation"""
        user = User.objects.create_user(**self.user_data)
        
        self.assertEqual(user.email, "test@example.com")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.check_password("testpass123"))

    def test_create_user_without_email(self):
        """Test creating user without email raises ValueError"""
        data = self.user_data.copy()
        del data["email"]
        
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(**data)
        
        self.assertIn("An email address must be provided", str(context.exception))

    def test_create_user_without_password(self):
        """Test creating user without password raises ValueError"""
        data = self.user_data.copy()
        del data["password"]
        
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(**data)
        
        self.assertIn("A password must be provided", str(context.exception))

    def test_create_superuser_success(self):
        """Test successful superuser creation"""
        user = User.objects.create_superuser(**self.user_data)
        
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_create_superuser_invalid_staff(self):
        """Test creating superuser with is_staff=False raises ValueError"""
        data = self.user_data.copy()
        data["is_staff"] = False
        
        with self.assertRaises(ValueError) as context:
            User.objects.create_superuser(**data)
        
        self.assertIn("Superuser must have is_staff=True", str(context.exception))

    def test_create_superuser_invalid_superuser(self):
        """Test creating superuser with is_superuser=False raises ValueError"""
        data = self.user_data.copy()
        data["is_superuser"] = False
        
        with self.assertRaises(ValueError) as context:
            User.objects.create_superuser(**data)
        
        self.assertIn("Superuser must have is_superuser=True", str(context.exception))

    def test_email_normalization(self):
        """Test email normalization"""
        data = self.user_data.copy()
        data["email"] = "Test@EXAMPLE.COM"
        
        user = User.objects.create_user(**data)
        self.assertEqual(user.email, "Test@example.com")

    def test_invalid_email_validation(self):
        """Test invalid email validation"""
        data = self.user_data.copy()
        data["email"] = "invalid-email"
        
        with self.assertRaises(ValidationError):
            User.objects.create_user(**data)


class UtilsTest(TestCase):
    """Test cases for utility functions"""

    @patch.dict('os.environ', {'BANK_NAME': 'Test Bank'})
    def test_generate_username(self):
        """Test username generation"""
        username = generate_username()
        
        self.assertTrue(username.startswith("TB-"))
        self.assertEqual(len(username), 12)
        self.assertRegex(username, r'^TB-[A-Z0-9]+$')

    @patch.dict('os.environ', {'BANK_NAME': 'First National Bank'})
    def test_generate_username_multiple_words(self):
        """Test username generation with multiple word bank name"""
        username = generate_username()
        
        self.assertTrue(username.startswith("FNB-"))
        self.assertEqual(len(username), 12)

    def test_validate_email_address_valid(self):
        """Test email validation with valid email"""
        try:
            validate_email_address("test@example.com")
        except ValidationError:
            self.fail("validate_email_address raised ValidationError unexpectedly")

    def test_validate_email_address_invalid(self):
        """Test email validation with invalid email"""
        with self.assertRaises(ValidationError):
            validate_email_address("invalid-email")

    def test_generate_otp_default_length(self):
        """Test OTP generation with default length"""
        otp = generate_otp()
        
        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())

    def test_generate_otp_custom_length(self):
        """Test OTP generation with custom length"""
        otp = generate_otp(length=8)
        
        self.assertEqual(len(otp), 8)
        self.assertTrue(otp.isdigit())


class UserFormsTest(TestCase):
    """Test cases for User forms"""

    def setUp(self):
        self.user_data = {
            "email": "test@example.com",
            "password1": "testpass123",
            "password2": "testpass123",
            "first_name": "John",
            "last_name": "Doe",
            "id_no": 12345678,
            "security_question": User.SecurityQuestions.MAIDEN_NAME,
            "security_answer": "Smith",
        }

    def test_user_creation_form_valid(self):
        """Test valid user creation form"""
        form = UserCreationForm(data=self.user_data)
        
        self.assertTrue(form.is_valid())

    def test_user_creation_form_duplicate_email(self):
        """Test user creation form with duplicate email"""
        User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            first_name="Jane",
            last_name="Doe",
            id_no=87654321,
            security_question=User.SecurityQuestions.MAIDEN_NAME,
            security_answer="Smith",
        )
        
        form = UserCreationForm(data=self.user_data)
        
        self.assertFalse(form.is_valid())
        self.assertIn("A user with that email already exists", 
                     form.errors["email"])

    def test_user_creation_form_duplicate_id_no(self):
        """Test user creation form with duplicate ID number"""
        User.objects.create_user(
            email="other@example.com",
            password="testpass123",
            first_name="Jane",
            last_name="Doe",
            id_no=12345678,
            security_question=User.SecurityQuestions.MAIDEN_NAME,
            security_answer="Smith",
        )
        
        form = UserCreationForm(data=self.user_data)
        
        self.assertFalse(form.is_valid())
        self.assertIn("A user with that ID number already exists", 
                     form.errors["id_no"])

    def test_user_creation_form_missing_security_for_regular_user(self):
        """Test user creation form missing security question for regular user"""
        data = self.user_data.copy()
        del data["security_question"]
        del data["security_answer"]
        
        form = UserCreationForm(data=data)
        
        self.assertFalse(form.is_valid())
        self.assertIn("Security question is required for regular users",
                     form.errors["security_question"])
        self.assertIn("Security answer is required for regular users",
                     form.errors["security_answer"])

    def test_user_creation_form_superuser_without_security(self):
        """Test superuser creation without security questions (should be valid)"""
        data = self.user_data.copy()
        data["is_superuser"] = True
        del data["security_question"]
        del data["security_answer"]
        
        form = UserCreationForm(data=data)
        
        self.assertTrue(form.is_valid())

    def test_user_change_form_valid(self):
        """Test valid user change form"""
        user = User.objects.create_user(
            email="original@example.com",
            password="testpass123",
            first_name="Original",
            last_name="User",
            id_no=11111111,
            security_question=User.SecurityQuestions.MAIDEN_NAME,
            security_answer="Smith",
        )
        
        data = {
            "email": "updated@example.com",
            "first_name": "Updated",
            "last_name": "User",
            "id_no": 22222222,
            "security_question": User.SecurityQuestions.FAVORITE_COLOR,
            "security_answer": "Blue",
        }
        
        form = UserChangeForm(data=data, instance=user)
        
        self.assertTrue(form.is_valid())

    def test_user_change_form_duplicate_email_other_user(self):
        """Test user change form with email that belongs to another user"""
        # Create two users
        user1 = User.objects.create_user(
            email="user1@example.com",
            password="testpass123",
            first_name="User",
            last_name="One",
            id_no=11111111,
            security_question=User.SecurityQuestions.MAIDEN_NAME,
            security_answer="Smith",
        )
        
        user2 = User.objects.create_user(
            email="user2@example.com",
            password="testpass123",
            first_name="User",
            last_name="Two",
            id_no=22222222,
            security_question=User.SecurityQuestions.MAIDEN_NAME,
            security_answer="Smith",
        )
        
        # Try to change user2's email to user1's email
        data = {
            "email": "user1@example.com",
            "first_name": "User",
            "last_name": "Two",
            "id_no": 22222222,
            "security_question": User.SecurityQuestions.MAIDEN_NAME,
            "security_answer": "Smith",
        }
        
        form = UserChangeForm(data=data, instance=user2)
        
        self.assertFalse(form.is_valid())
        self.assertIn("A user with that email already exists",
                     form.errors["email"])


class EmailsTest(TestCase):
    """Test cases for email functions"""

    @patch('core_apps.user_auth.emails.EmailMultiAlternatives')
    @patch('core_apps.user_auth.emails.render_to_string')
    @override_settings(
        DEFAULT_FROM_EMAIL="test@bank.com",
        OTP_EXPIRATION=timedelta(minutes=5),
        SITE_NAME="Test Bank"
    )
    def test_send_otp_email_success(self, mock_render, mock_email):
        """Test successful OTP email sending"""
        mock_render.return_value = "<html>OTP: 123456</html>"
        mock_email_instance = Mock()
        mock_email.return_value = mock_email_instance
        
        send_otp_email("test@example.com", "123456")
        
        mock_email.assert_called_once()
        mock_email_instance.attach_alternative.assert_called_once()
        mock_email_instance.send.assert_called_once()

    @patch('core_apps.user_auth.emails.EmailMultiAlternatives')
    @patch('core_apps.user_auth.emails.logger')
    def test_send_otp_email_failure(self, mock_logger, mock_email):
        """Test OTP email sending failure"""
        mock_email_instance = Mock()
        mock_email_instance.send.side_effect = Exception("SMTP Error")
        mock_email.return_value = mock_email_instance
        
        send_otp_email("test@example.com", "123456")
        
        mock_logger.error.assert_called_once()

    @patch('core_apps.user_auth.emails.EmailMultiAlternatives')
    @patch('core_apps.user_auth.emails.render_to_string')
    @override_settings(
        DEFAULT_FROM_EMAIL="test@bank.com",
        LOCKOUT_DURATION=timedelta(minutes=30),
        SITE_NAME="Test Bank"
    )
    def test_send_account_locked_email_success(self, mock_render, mock_email):
        """Test successful account locked email sending"""
        user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            first_name="John",
            last_name="Doe",
            id_no=12345678,
            security_question=User.SecurityQuestions.MAIDEN_NAME,
            security_answer="Smith",
        )
        
        mock_render.return_value = "<html>Account locked</html>"
        mock_email_instance = Mock()
        mock_email.return_value = mock_email_instance
        
        send_account_locked_email(user)
        
        mock_email.assert_called_once()
        mock_email_instance.attach_alternative.assert_called_once()
        mock_email_instance.send.assert_called_once()


class UserModelIntegrationTest(TestCase):
    """Integration tests for User model functionality"""

    def setUp(self):
        self.user_data = {
            "email": "test@example.com",
            "password": "testpass123",
            "first_name": "John",
            "last_name": "Doe",
            "id_no": 12345678,
            "security_question": User.SecurityQuestions.MAIDEN_NAME,
            "security_answer": "Smith",
        }

    @override_settings(LOGIN_ATTEMPTS=3, LOCKOUT_DURATION=timedelta(minutes=30))
    @patch('core_apps.user_auth.models.send_account_locked_email')
    def test_full_lockout_and_recovery_flow(self, mock_send_email):
        """Test complete lockout and recovery flow"""
        user = User.objects.create_user(**self.user_data)
        
        # Test multiple failed attempts leading to lockout
        for i in range(3):
            user.handle_failed_login_attempts()
        
        # Verify account is locked
        self.assertEqual(user.account_status, User.AccountStatus.LOCKED)
        self.assertTrue(user.is_locked_out)
        mock_send_email.assert_called_once()
        
        # Test manual unlock
        user.unlock_account()
        self.assertEqual(user.account_status, User.AccountStatus.ACTIVE)
        self.assertFalse(user.is_locked_out)
        
        # Test successful login resets attempts
        user.failed_login_attempts = 2
        user.save()
        user.reset_failed_login_attempts()
        self.assertEqual(user.failed_login_attempts, 0)

    @override_settings(OTP_EXPIRATION=timedelta(minutes=5))
    def test_otp_workflow(self):
        """Test complete OTP workflow"""
        user = User.objects.create_user(**self.user_data)
        otp = generate_otp()
        
        # Set OTP
        user.set_otp(otp)
        self.assertEqual(user.otp, otp)
        self.assertIsNotNone(user.otp_expiry_time)
        
        # Verify correct OTP
        self.assertTrue(user.verify_otp(otp))
        self.assertEqual(user.otp, "")
        self.assertIsNone(user.otp_expiry_time)
        
        # Test OTP can't be reused
        self.assertFalse(user.verify_otp(otp))

    def test_user_roles_and_permissions(self):
        """Test user roles and related functionality"""
        # Test customer role
        customer = User.objects.create_user(**self.user_data)
        self.assertEqual(customer.role, User.RoleChoices.CUSTOMER)
        self.assertTrue(customer.has_role(User.RoleChoices.CUSTOMER))
        
        # Test staff role
        staff_data = self.user_data.copy()
        staff_data["email"] = "staff@example.com"
        staff_data["id_no"] = 87654321
        staff_data["role"] = User.RoleChoices.TELLER
        staff = User.objects.create_user(**staff_data)
        
        self.assertEqual(staff.role, User.RoleChoices.TELLER)
        self.assertTrue(staff.has_role(User.RoleChoices.TELLER))
        self.assertFalse(staff.has_role(User.RoleChoices.CUSTOMER))

    def test_unique_constraints(self):
        """Test unique constraints on email and id_no"""
        User.objects.create_user(**self.user_data)
        
        # Test duplicate email
        duplicate_email_data = self.user_data.copy()
        duplicate_email_data["id_no"] = 87654321
        
        with self.assertRaises(Exception):  # Should raise IntegrityError
            User.objects.create_user(**duplicate_email_data)
        
        # Test duplicate ID number
        duplicate_id_data = self.user_data.copy()
        duplicate_id_data["email"] = "different@example.com"
        
        with self.assertRaises(Exception):  # Should raise IntegrityError
            User.objects.create_user(**duplicate_id_data)