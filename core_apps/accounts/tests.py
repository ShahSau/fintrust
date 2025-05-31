import os
import tempfile
from decimal import Decimal
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.core import mail
from django.test.utils import override_settings

from core_apps.accounts.models import BankAccount, Transaction
from core_apps.accounts.serializers import (
    AccountVerificationSerializer,
    DepositSerializer,
    TransactionSerializer,
    CustomerInfoSerializer,
    SecurityQuestionSerializer,
    OTPVerificationSerializer,
    UsernameVerificationSerializer,
)
from core_apps.accounts.utils import (
    generate_account_number,
    calculate_luhn_check_digit,
    create_bank_account,
)
from core_apps.accounts.emails import (
    send_account_creation_email,
    send_full_activation_email,
    send_deposit_email,
    send_withdrawal_email,
    send_transfer_email,
    send_transfer_otp_email,
)
from core_apps.accounts.tasks import generate_transaction_pdf

User = get_user_model()


class BankAccountModelTest(TestCase):
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.verifier = User.objects.create_user(
            email='verifier@example.com',
            username='verifier',
            password='testpass123',
            is_staff=True
        )

    def test_bank_account_creation(self):
        """Test basic bank account creation"""
        account = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT
        )
        
        self.assertEqual(account.user, self.user)
        self.assertEqual(account.currency, BankAccount.AccountCurrency.DOLLAR)
        self.assertEqual(account.account_type, BankAccount.AccountType.CURRENT)
        self.assertEqual(account.account_balance, Decimal('0.00'))
        self.assertEqual(account.account_status, BankAccount.AccountStatus.INACTIVE)
        self.assertFalse(account.is_primary)
        self.assertFalse(account.kyc_verified)

    def test_bank_account_str_representation(self):
        """Test string representation of bank account"""
        account = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT
        )
        
        expected_str = f"{self.user.full_name}'s US Dollar - Current Account - 1234567890123456"
        self.assertEqual(str(account), expected_str)

    def test_negative_balance_validation(self):
        """Test that negative balance raises validation error"""
        account = BankAccount(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            account_balance=Decimal('-100.00')
        )
        
        with self.assertRaises(ValidationError):
            account.clean()

    def test_primary_account_logic(self):
        """Test that only one account can be primary per user"""
        account1 = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            is_primary=True
        )
        
        account2 = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123457',
            currency=BankAccount.AccountCurrency.EURO,
            account_type=BankAccount.AccountType.SAVINGS,
            is_primary=True
        )
        
        # Refresh from database
        account1.refresh_from_db()
        account2.refresh_from_db()
        
        # Only the latest account should be primary
        self.assertFalse(account1.is_primary)
        self.assertTrue(account2.is_primary)

    def test_unique_together_constraint(self):
        """Test unique constraint on user, currency, and account_type"""
        BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT
        )
        
        # Creating another account with same user, currency, and type should raise error
        with self.assertRaises(Exception):
            BankAccount.objects.create(
                user=self.user,
                account_number='1234567890123457',
                currency=BankAccount.AccountCurrency.DOLLAR,
                account_type=BankAccount.AccountType.CURRENT
            )


class TransactionModelTest(TestCase):
    def setUp(self):
        """Set up test data"""
        self.sender = User.objects.create_user(
            email='sender@example.com',
            username='sender',
            password='testpass123'
        )
        self.receiver = User.objects.create_user(
            email='receiver@example.com',
            username='receiver',
            password='testpass123'
        )
        
        self.sender_account = BankAccount.objects.create(
            user=self.sender,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            account_balance=Decimal('1000.00')
        )
        
        self.receiver_account = BankAccount.objects.create(
            user=self.receiver,
            account_number='1234567890123457',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.SAVINGS,
            account_balance=Decimal('500.00')
        )

    def test_transaction_creation(self):
        """Test basic transaction creation"""
        transaction = Transaction.objects.create(
            user=self.sender,
            sender=self.sender,
            receiver=self.receiver,
            sender_account=self.sender_account,
            receiver_account=self.receiver_account,
            amount=Decimal('100.00'),
            description='Test transfer',
            transaction_type=Transaction.TransactionType.TRANSFER
        )
        
        self.assertEqual(transaction.amount, Decimal('100.00'))
        self.assertEqual(transaction.transaction_type, Transaction.TransactionType.TRANSFER)
        self.assertEqual(transaction.status, Transaction.TransactionStatus.PENDING)
        self.assertEqual(transaction.sender, self.sender)
        self.assertEqual(transaction.receiver, self.receiver)

    def test_transaction_str_representation(self):
        """Test string representation of transaction"""
        transaction = Transaction.objects.create(
            user=self.sender,
            amount=Decimal('100.00'),
            transaction_type=Transaction.TransactionType.DEPOSIT,
            status=Transaction.TransactionStatus.COMPLETED
        )
        
        expected_str = "deposit - 100.00 - completed"
        self.assertEqual(str(transaction), expected_str)

    def test_transaction_ordering(self):
        """Test that transactions are ordered by creation date descending"""
        transaction1 = Transaction.objects.create(
            user=self.sender,
            amount=Decimal('100.00'),
            transaction_type=Transaction.TransactionType.DEPOSIT
        )
        
        transaction2 = Transaction.objects.create(
            user=self.sender,
            amount=Decimal('200.00'),
            transaction_type=Transaction.TransactionType.WITHDRAWAL
        )
        
        transactions = Transaction.objects.all()
        self.assertEqual(transactions[0], transaction2)  # Most recent first
        self.assertEqual(transactions[1], transaction1)


class UtilsTest(TestCase):
    @override_settings(
        BANK_CODE='123',
        BANK_BRANCH_CODE='456',
        CURRENCY_CODE_USD='001',
        CURRENCY_CODE_GBP='002',
        CURRENCY_CODE_EUR='003'
    )
    def test_generate_account_number(self):
        """Test account number generation"""
        account_number = generate_account_number('us_dollar')
        
        # Should start with bank code + branch code + currency code
        self.assertTrue(account_number.startswith('123456001'))
        # Should be 16 digits total
        self.assertEqual(len(account_number), 16)
        # Should be all digits
        self.assertTrue(account_number.isdigit())

    def test_generate_account_number_invalid_currency(self):
        """Test account number generation with invalid currency"""
        with self.assertRaises(ValueError):
            generate_account_number('invalid_currency')

    def test_calculate_luhn_check_digit(self):
        """Test Luhn check digit calculation"""
        # Known test case
        check_digit = calculate_luhn_check_digit('123456789012345')
        self.assertIsInstance(check_digit, int)
        self.assertGreaterEqual(check_digit, 0)
        self.assertLessEqual(check_digit, 9)

    @patch('core_apps.accounts.utils.send_account_creation_email')
    def test_create_bank_account(self, mock_send_email):
        """Test bank account creation utility"""
        user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        
        account = create_bank_account(user, 'us_dollar', 'current')
        
        self.assertEqual(account.user, user)
        self.assertEqual(account.currency, 'us_dollar')
        self.assertEqual(account.account_type, 'current')
        self.assertTrue(account.is_primary)  # First account should be primary
        mock_send_email.assert_called_once_with(user, account)


class EmailTest(TestCase):
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.account = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            account_balance=Decimal('1000.00')
        )

    @override_settings(DEFAULT_FROM_EMAIL='test@bank.com', SITE_NAME='Test Bank')
    def test_send_account_creation_email(self):
        """Test account creation email"""
        send_account_creation_email(self.user, self.account)
        
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.to, ['test@example.com'])
        self.assertIn('Your New Bank Account has been Created', email.subject)

    @override_settings(DEFAULT_FROM_EMAIL='test@bank.com', SITE_NAME='Test Bank')
    def test_send_deposit_email(self):
        """Test deposit confirmation email"""
        send_deposit_email(
            user=self.user,
            user_email=self.user.email,
            amount=Decimal('500.00'),
            currency='US Dollar',
            new_balance=Decimal('1500.00'),
            account_number=self.account.account_number
        )
        
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.to, ['test@example.com'])
        self.assertIn('Deposit Confirmation', email.subject)

    @override_settings(DEFAULT_FROM_EMAIL='test@bank.com', SITE_NAME='Test Bank')
    def test_send_transfer_otp_email(self):
        """Test transfer OTP email"""
        send_transfer_otp_email('test@example.com', '123456')
        
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.to, ['test@example.com'])
        self.assertIn('Your OTP for Transfer Authorization', email.subject)


class SerializerTest(TestCase):
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.account = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            account_balance=Decimal('1000.00')
        )

    def test_account_verification_serializer_valid(self):
        """Test valid account verification data"""
        data = {
            'kyc_submitted': True,
            'kyc_verified': True,
            'verification_date': timezone.now(),
            'verification_notes': 'Account verified successfully',
            'account_status': BankAccount.AccountStatus.ACTIVE
        }
        
        serializer = AccountVerificationSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_account_verification_serializer_invalid(self):
        """Test invalid account verification data"""
        data = {
            'kyc_verified': True,
            # Missing required verification_date and verification_notes
        }
        
        serializer = AccountVerificationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('Verification date is required', str(serializer.errors))

    def test_deposit_serializer_valid(self):
        """Test valid deposit data"""
        data = {
            'account_number': '1234567890123456',
            'amount': '500.00'
        }
        
        serializer = DepositSerializer(data=data)
        serializer.context = {}
        self.assertTrue(serializer.is_valid())

    def test_deposit_serializer_invalid_account(self):
        """Test deposit with invalid account number"""
        data = {
            'account_number': 'invalid_account',
            'amount': '500.00'
        }
        
        serializer = DepositSerializer(data=data)
        serializer.context = {}
        self.assertFalse(serializer.is_valid())
        self.assertIn('Invalid account number', str(serializer.errors))

    def test_transaction_serializer_transfer_validation(self):
        """Test transaction serializer for transfer"""
        receiver_account = BankAccount.objects.create(
            user=User.objects.create_user(
                email='receiver@example.com',
                username='receiver',
                password='testpass123'
            ),
            account_number='1234567890123457',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.SAVINGS,
            account_balance=Decimal('500.00')
        )
        
        data = {
            'transaction_type': Transaction.TransactionType.TRANSFER,
            'sender_account': '1234567890123456',
            'receiver_account': '1234567890123457',
            'amount': '100.00',
            'description': 'Test transfer'
        }
        
        serializer = TransactionSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_transaction_serializer_insufficient_funds(self):
        """Test transaction serializer with insufficient funds"""
        data = {
            'transaction_type': Transaction.TransactionType.WITHDRAWAL,
            'sender_account': '1234567890123456',
            'amount': '2000.00'  # More than account balance
        }
        
        serializer = TransactionSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('Insufficient funds', str(serializer.errors))


class ViewTest(APITestCase):
    def setUp(self):
        """Set up test data and authentication"""
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.teller = User.objects.create_user(
            email='teller@example.com',
            username='teller',
            password='testpass123',
            is_staff=True
        )
        # Add teller to appropriate group for IsTeller permission
        
        self.account_executive = User.objects.create_user(
            email='executive@example.com',
            username='executive',
            password='testpass123',
            is_staff=True
        )
        # Add executive to appropriate group for IsAccountExecutive permission
        
        self.account = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            account_balance=Decimal('1000.00'),
            fully_activated=True,
            kyc_verified=True
        )
        
        self.client = APIClient()

    def test_deposit_view_get_customer_info(self):
        """Test getting customer info for deposit"""
        self.client.force_authenticate(user=self.teller)
        
        url = reverse('account_deposit')
        response = self.client.get(url, {'account_number': '1234567890123456'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['account_number'], '1234567890123456')
        self.assertEqual(response.data['full_name'], self.user.full_name)

    def test_deposit_view_post(self):
        """Test making a deposit"""
        self.client.force_authenticate(user=self.teller)
        
        url = reverse('account_deposit')
        data = {
            'account_number': '1234567890123456',
            'amount': '500.00'
        }
        
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Successfully deposited', response.data['message'])
        
        # Check that balance was updated
        self.account.refresh_from_db()
        self.assertEqual(self.account.account_balance, Decimal('1500.00'))

    def test_initiate_withdrawal_view(self):
        """Test initiating withdrawal"""
        self.client.force_authenticate(user=self.user)
        
        url = reverse('initiate_withdrawal')
        data = {
            'account_number': '1234567890123456',
            'amount': '200.00'
        }
        
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Withdrawal Initiated', response.data['message'])

    def test_initiate_transfer_view(self):
        """Test initiating transfer"""
        # Create receiver account
        receiver = User.objects.create_user(
            email='receiver@example.com',
            username='receiver',
            password='testpass123'
        )
        receiver_account = BankAccount.objects.create(
            user=receiver,
            account_number='1234567890123457',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.SAVINGS,
            account_balance=Decimal('500.00')
        )
        
        self.client.force_authenticate(user=self.user)
        
        url = reverse('initiate_transfer')
        data = {
            'sender_account': '1234567890123456',
            'receiver_account': '1234567890123457',
            'amount': '100.00',
            'description': 'Test transfer'
        }
        
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('security question', response.data['message'])

    def test_transaction_list_view(self):
        """Test getting transaction list"""
        # Create some transactions
        Transaction.objects.create(
            user=self.user,
            sender=self.user,
            sender_account=self.account,
            amount=Decimal('100.00'),
            transaction_type=Transaction.TransactionType.DEPOSIT,
            status=Transaction.TransactionStatus.COMPLETED
        )
        
        self.client.force_authenticate(user=self.user)
        
        url = reverse('transaction_list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)

    def test_transaction_pdf_view(self):
        """Test generating transaction PDF"""
        self.client.force_authenticate(user=self.user)
        
        url = reverse('transaction_pdf')
        data = {
            'start_date': (timezone.now() - timedelta(days=30)).isoformat(),
            'end_date': timezone.now().isoformat()
        }
        
        with patch('core_apps.accounts.views.generate_transaction_pdf.delay') as mock_task:
            response = self.client.post(url, data)
            
            self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
            self.assertIn('PDF is being generated', response.data['message'])
            mock_task.assert_called_once()

    def test_unauthorized_access(self):
        """Test unauthorized access to protected endpoints"""
        url = reverse('account_deposit')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_insufficient_permissions(self):
        """Test access with insufficient permissions"""
        self.client.force_authenticate(user=self.user)  # Regular user, not teller
        
        url = reverse('account_deposit')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class TaskTest(TestCase):
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.account = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            account_balance=Decimal('1000.00')
        )
        
        # Create some transactions
        Transaction.objects.create(
            user=self.user,
            sender=self.user,
            sender_account=self.account,
            amount=Decimal('100.00'),
            transaction_type=Transaction.TransactionType.DEPOSIT,
            status=Transaction.TransactionStatus.COMPLETED
        )

    @patch('core_apps.accounts.tasks.EmailMessage')
    @override_settings(DEFAULT_FROM_EMAIL='test@bank.com')
    def test_generate_transaction_pdf_task(self, mock_email):
        """Test transaction PDF generation task"""
        mock_email_instance = MagicMock()
        mock_email.return_value = mock_email_instance
        mock_email_instance.send.return_value = True
        
        start_date = (timezone.now() - timedelta(days=30)).date().isoformat()
        end_date = timezone.now().date().isoformat()
        
        result = generate_transaction_pdf(
            self.user.id,
            start_date,
            end_date,
            self.account.account_number
        )
        
        self.assertIn('PDF generated and sent', result)
        mock_email.assert_called_once()
        mock_email_instance.attach.assert_called_once()
        mock_email_instance.send.assert_called_once()


class AdminTest(TestCase):
    def setUp(self):
        """Set up test data"""
        self.superuser = User.objects.create_superuser(
            email='admin@example.com',
            username='admin',
            password='adminpass123'
        )
        
        self.staff_user = User.objects.create_user(
            email='staff@example.com',
            username='staff',
            password='staffpass123',
            is_staff=True
        )
        
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            username='user',
            password='userpass123'
        )
        
        self.account = BankAccount.objects.create(
            user=self.regular_user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            verified_by=self.staff_user
        )

    def test_admin_queryset_superuser(self):
        """Test admin queryset for superuser"""
        from core_apps.accounts.admin import BankAccountAdmin
        from django.http import HttpRequest
        
        admin = BankAccountAdmin(BankAccount, None)
        request = HttpRequest()
        request.user = self.superuser
        
        qs = admin.get_queryset(request)
        self.assertEqual(qs.count(), 1)

    def test_admin_queryset_staff_user(self):
        """Test admin queryset for staff user"""
        from core_apps.accounts.admin import BankAccountAdmin
        from django.http import HttpRequest
        
        admin = BankAccountAdmin(BankAccount, None)
        request = HttpRequest()
        request.user = self.staff_user
        
        qs = admin.get_queryset(request)
        self.assertEqual(qs.count(), 1)  # Should see accounts they verified

    def test_admin_has_change_permission(self):
        """Test admin change permissions"""
        from core_apps.accounts.admin import BankAccountAdmin
        from django.http import HttpRequest
        
        admin = BankAccountAdmin(BankAccount, None)
        request = HttpRequest()
        request.user = self.staff_user
        
        # Should have permission for accounts they verified
        self.assertTrue(admin.has_change_permission(request, self.account))
        
        # Test with different staff user
        other_staff = User.objects.create_user(
            email='other@example.com',
            username='other',
            password='otherpass123',
            is_staff=True
        )
        request.user = other_staff
        self.assertFalse(admin.has_change_permission(request, self.account))


class IntegrationTest(APITestCase):
    """Integration tests for complete workflows"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123',
            first_name='Test',
            last_name='User',
            security_answer='test_answer'
        )
        
        self.receiver = User.objects.create_user(
            email='receiver@example.com',
            username='receiver',
            password='testpass123',
            first_name='Receiver',
            last_name='User'
        )
        
        self.sender_account = BankAccount.objects.create(
            user=self.user,
            account_number='1234567890123456',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.CURRENT,
            account_balance=Decimal('1000.00'),
            fully_activated=True,
            kyc_verified=True
        )
        
        self.receiver_account = BankAccount.objects.create(
            user=self.receiver,
            account_number='1234567890123457',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.SAVINGS,
            account_balance=Decimal('500.00')
        )
        
        self.client = APIClient()

    def test_complete_transfer_workflow(self):
        """Test complete transfer workflow"""
        self.client.force_authenticate(user=self.user)
        
        # Step 1: Initiate transfer
        url = reverse('initiate_transfer')
        data = {
            'sender_account': '1234567890123456',
            'receiver_account': '1234567890123457',
            'amount': '100.00',
            'description': 'Test transfer'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Step 2: Verify security question
        url = reverse('verify_security_question')
        data = {'security_answer': 'test_answer'}
        
        with patch.object(self.user, 'set_otp') as mock_set_otp:
            response = self.client.post(url, data)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            mock_set_otp.assert_called_once()
        
        # Step 3: Verify OTP
        url = reverse('verify_otp')
        data = {'otp': '123456'}
        
        with patch.object(self.user, 'verify_otp', return_value=True):
            response = self.client.post(url, data)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify balances were updated
        self.sender_account.refresh_from_db()
        self.receiver_account.refresh_from_db()
        
        self.assertEqual(self.sender_account.account_balance, Decimal('900.00'))
        self.assertEqual(self.receiver_account.account_balance, Decimal('600.00'))
        
        # Verify transaction was created
        transaction = Transaction.objects.filter(
            transaction_type=Transaction.TransactionType.TRANSFER
        ).first()
        self.assertIsNotNone(transaction)
        self.assertEqual(transaction.amount, Decimal('100.00'))
        

        self.assertEqual(transaction.sender_account, self.sender_account)
        self.assertEqual(transaction.receiver_account, self.receiver_account)
        self.assertEqual(transaction.sender, self.user)
        self.assertEqual(transaction.receiver, self.receiver)
        self.assertEqual(transaction.status, Transaction.TransactionStatus.COMPLETED)
    def test_complete_deposit_workflow(self):
        """Test complete deposit workflow"""
        self.client.force_authenticate(user=self.user)
        
        # Step 1: Get customer info
        url = reverse('account_deposit')
        response = self.client.get(url, {'account_number': '1234567890123456'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Step 2: Make deposit
        data = {
            'account_number': '1234567890123456',
            'amount': '500.00'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify account balance was updated
        self.sender_account.refresh_from_db()
        self.assertEqual(self.sender_account.account_balance, Decimal('1500.00'))
        
        # Verify transaction was created
        transaction = Transaction.objects.filter(
            transaction_type=Transaction.TransactionType.DEPOSIT
        ).first()
        self.assertIsNotNone(transaction)
        self.assertEqual(transaction.amount, Decimal('500.00'))
        self.assertEqual(transaction.sender_account, self.sender_account)
        self.assertEqual(transaction.status, Transaction.TransactionStatus.COMPLETED)
    def test_complete_withdrawal_workflow(self):
        """Test complete withdrawal workflow"""
        self.client.force_authenticate(user=self.user)
        
        # Step 1: Initiate withdrawal
        url = reverse('initiate_withdrawal')
        data = {
            'account_number': '1234567890123456',
            'amount': '200.00'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify account balance was updated
        self.sender_account.refresh_from_db()
        self.assertEqual(self.sender_account.account_balance, Decimal('800.00'))
        
        # Verify transaction was created
        transaction = Transaction.objects.filter(
            transaction_type=Transaction.TransactionType.WITHDRAWAL
        ).first()
        self.assertIsNotNone(transaction)
        self.assertEqual(transaction.amount, Decimal('200.00'))
        self.assertEqual(transaction.sender_account, self.sender_account)
        self.assertEqual(transaction.status, Transaction.TransactionStatus.COMPLETED)
    def test_complete_account_verification_workflow(self):
        """Test complete account verification workflow"""
        self.client.force_authenticate(user=self.teller)
        
        # Step 1: Get customer info
        url = reverse('account_verification')
        response = self.client.get(url, {'account_number': '1234567890123456'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Step 2: Submit verification
        data = {
            'kyc_submitted': True,
            'kyc_verified': True,
            'verification_date': timezone.now().isoformat(),
            'verification_notes': 'Account verified successfully',
            'account_status': BankAccount.AccountStatus.ACTIVE
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify account was updated
        self.sender_account.refresh_from_db()
        self.assertTrue(self.sender_account.kyc_verified)
        self.assertEqual(self.sender_account.account_status, BankAccount.AccountStatus.ACTIVE)
        self.assertEqual(self.sender_account.verified_by, self.teller)
    def test_complete_security_question_workflow(self):
        """Test complete security question workflow"""
        self.client.force_authenticate(user=self.user)
        
        # Step 1: Get security question
        url = reverse('security_question')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Step 2: Verify security question answer
        data = {'security_answer': 'test_answer'}
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify OTP was set
        self.assertTrue(self.user.otp_set)
        # Verify OTP was sent
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertIn('Your OTP for Transfer Authorization', email.subject)
    def test_complete_otp_verification_workflow(self):
        """Test complete OTP verification workflow"""
        self.client.force_authenticate(user=self.user)
        
        # Step 1: Set OTP
        self.user.set_otp('123456')
        self.user.save()
        # Step 2: Verify OTP
        url = reverse('verify_otp')
        data = {'otp': '123456'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Verify OTP was verified
        self.assertTrue(self.user.otp_verified)
        # Verify OTP was sent
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertIn('Your OTP for Transfer Authorization', email.subject)
    def test_username_verification(self):
        """Test username verification workflow"""
        self.client.force_authenticate(user=self.user)
        
        # Step 1: Get username verification
        url = reverse('username_verification')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Step 2: Verify username
        data = {'username': 'testuser'}
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify username was verified
        self.assertTrue(self.user.username_verified)
        # Verify email was sent
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertIn('Username Verification Successful', email.subject)
    def test_customer_info_serializer(self):
        """Test CustomerInfoSerializer"""
        serializer = CustomerInfoSerializer(instance=self.user)
        data = serializer.data
        
        self.assertEqual(data['email'], self.user.email)
        self.assertEqual(data['full_name'], self.user.full_name)
        self.assertEqual(data['account_number'], self.account.account_number)
        self.assertEqual(data['account_balance'], str(self.account.account_balance))
        self.assertEqual(data['currency'], self.account.currency)
        self.assertEqual(data['account_type'], self.account.account_type)
    def test_security_question_serializer(self):
        """Test SecurityQuestionSerializer"""
        serializer = SecurityQuestionSerializer(instance=self.user)
        data = serializer.data
        
        self.assertIn('security_question', data)
        self.assertIn('security_answer', data)
        self.assertEqual(data['security_question'], self.user.security_question)
        self.assertEqual(data['security_answer'], self.user.security_answer)
    def test_otp_verification_serializer(self):
        """Test OTPVerificationSerializer"""
        serializer = OTPVerificationSerializer(instance=self.user)
        data = serializer.data
        self.assertIn('otp', data)
        self.assertIn('otp_verified', data)
        self.assertEqual(data['otp_verified'], self.user.otp_verified)
    def test_username_verification_serializer(self):
        """Test UsernameVerificationSerializer"""   
        serializer = UsernameVerificationSerializer(instance=self.user)
        data = serializer.data
        
        self.assertIn('username', data)
        self.assertEqual(data['username'], self.user.username)
        self.assertEqual(data['username_verified'], self.user.username_verified)
    def test_account_verification_serializer(self):
        """Test AccountVerificationSerializer"""
        serializer = AccountVerificationSerializer(instance=self.account)
        data = serializer.data
        
        self.assertIn('kyc_submitted', data)
        self.assertIn('kyc_verified', data)
        self.assertIn('verification_date', data)
        self.assertIn('verification_notes', data)
        self.assertIn('account_status', data)
        
        self.assertEqual(data['kyc_submitted'], self.account.kyc_submitted)
        self.assertEqual(data['kyc_verified'], self.account.kyc_verified)
        self.assertEqual(data['account_status'], self.account.account_status)
    def test_deposit_serializer(self):
        """Test DepositSerializer"""
        serializer = DepositSerializer(data={
            'account_number': self.account.account_number,
            'amount': '500.00'
        })
        serializer.context = {'request': self.client}
        
        self.assertTrue(serializer.is_valid())
        data = serializer.validated_data
        
        self.assertEqual(data['account_number'], self.account.account_number)
        self.assertEqual(data['amount'], Decimal('500.00'))
    def test_transaction_serializer(self):
        """Test TransactionSerializer"""
        serializer = TransactionSerializer(data={
            'transaction_type': Transaction.TransactionType.DEPOSIT,
            'sender_account': self.account.account_number,
            'amount': '100.00',
            'description': 'Test deposit'
        })
        
        serializer.context = {'request': self.client}
        
        self.assertTrue(serializer.is_valid())
        data = serializer.validated_data
        
        self.assertEqual(data['transaction_type'], Transaction.TransactionType.DEPOSIT)
        self.assertEqual(data['sender_account'], self.account.account_number)
        self.assertEqual(data['amount'], Decimal('100.00'))
        self.assertEqual(data['description'], 'Test deposit')
    def test_transaction_serializer_transfer_validation(self):
        """Test transaction serializer for transfer"""
        receiver_account = BankAccount.objects.create(
            user=self.receiver,
            account_number='1234567890123458',
            currency=BankAccount.AccountCurrency.DOLLAR,
            account_type=BankAccount.AccountType.SAVINGS,
            account_balance=Decimal('500.00')
        )
        
        data = {
            'transaction_type': Transaction.TransactionType.TRANSFER,
            'sender_account': self.sender_account.account_number,
            'receiver_account': receiver_account.account_number,
            'amount': '100.00',
            'description': 'Test transfer'
        }
        
        serializer = TransactionSerializer(data=data)
        serializer.context = {'request': self.client}
        
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['receiver_account'], receiver_account.account_number)
        self.assertEqual(serializer.validated_data['sender_account'], self.sender_account.account_number)
        self.assertEqual(serializer.validated_data['amount'], Decimal('100.00'))
        self.assertEqual(serializer.validated_data['description'], 'Test transfer')
        
        