import json
from decimal import Decimal
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.urls import reverse
from django.core import mail
from rest_framework.test import APITestCase
from rest_framework import status
from core_apps.accounts.models import BankAccount, Transaction
from core_apps.cards.models import VirtualCard
from core_apps.cards.serializers import VirtualCardSerializer, VirtualCardCreateSerializer
from core_apps.cards.utils import generate_card_number, generate_cvv
from core_apps.cards.emails import send_virtual_card_topup_email

User = get_user_model()


class VirtualCardModelTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.bank_account = BankAccount.objects.create(
            user=self.user,
            account_number="1234567890",
            account_balance=Decimal("1000.00"),
            currency="USD"
        )

    def test_virtual_card_creation(self):
        """Test creating a virtual card"""
        virtual_card = VirtualCard.objects.create(
            user=self.user,
            bank_account=self.bank_account,
            card_number="1234567890123456",
            expiry_date=timezone.now() + timezone.timedelta(days=365),
            cvv="123",
            balance=Decimal("100.00")
        )
        
        self.assertEqual(virtual_card.user, self.user)
        self.assertEqual(virtual_card.bank_account, self.bank_account)
        self.assertEqual(virtual_card.card_number, "1234567890123456")
        self.assertEqual(virtual_card.balance, Decimal("100.00"))
        self.assertEqual(virtual_card.status, VirtualCard.CardStatus.ACTIVE)

    def test_virtual_card_str_method(self):
        """Test the string representation of virtual card"""
        virtual_card = VirtualCard.objects.create(
            user=self.user,
            bank_account=self.bank_account,
            card_number="1234567890123456",
            expiry_date=timezone.now() + timezone.timedelta(days=365),
            cvv="123"
        )
        
        expected_str = f"Virtual Card 1234567890123456 for {self.user.full_name}"
        self.assertEqual(str(virtual_card), expected_str)

    def test_card_status_choices(self):
        """Test card status choices"""
        self.assertEqual(VirtualCard.CardStatus.ACTIVE, "active")
        self.assertEqual(VirtualCard.CardStatus.INACTIVE, "inactive")
        self.assertEqual(VirtualCard.CardStatus.BLOCKED, "blocked")


class VirtualCardUtilsTestCase(TestCase):
    @patch.dict('os.environ', {'BANK_CARD_PREFIX': '1234', 'BANK_CARD_CODE': '56'})
    def test_generate_card_number(self):
        """Test card number generation"""
        card_number = generate_card_number()
        
        self.assertEqual(len(card_number), 16)
        self.assertTrue(card_number.startswith('123456'))
        self.assertTrue(card_number.isdigit())

    @patch.dict('os.environ', {'BANK_CARD_PREFIX': '1234', 'BANK_CARD_CODE': '56'})
    def test_generate_card_number_custom_length(self):
        """Test card number generation with custom length"""
        card_number = generate_card_number(length=15)
        self.assertEqual(len(card_number), 15)

    @patch.dict('os.environ', {'BANK_CARD_PREFIX': '12345678901234', 'BANK_CARD_CODE': '56'})
    def test_generate_card_number_prefix_too_long(self):
        """Test card number generation with prefix too long"""
        with self.assertRaises(ValueError):
            generate_card_number(length=16)

    @patch.dict('os.environ', {'CVV_SECRET_KEY': 'test_secret_key'})
    def test_generate_cvv(self):
        """Test CVV generation"""
        card_number = "1234567890123456"
        expiry_date = "1225"
        
        cvv = generate_cvv(card_number, expiry_date)
        
        self.assertEqual(len(cvv), 3)
        self.assertTrue(cvv.isdigit())
        
        # Test consistency - same inputs should produce same CVV
        cvv2 = generate_cvv(card_number, expiry_date)
        self.assertEqual(cvv, cvv2)


class VirtualCardSerializerTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.bank_account = BankAccount.objects.create(
            user=self.user,
            account_number="1234567890",
            account_balance=Decimal("1000.00"),
            currency="USD"
        )
        self.virtual_card = VirtualCard.objects.create(
            user=self.user,
            bank_account=self.bank_account,
            card_number="1234567890123456",
            expiry_date=timezone.now() + timezone.timedelta(days=365),
            cvv="123",
            balance=Decimal("100.00")
        )

    def test_virtual_card_serializer(self):
        """Test VirtualCardSerializer"""
        serializer = VirtualCardSerializer(self.virtual_card)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertEqual(data['card_number'], "1234567890123456")
        self.assertEqual(data['cvv'], "123")
        self.assertEqual(Decimal(data['balance']), Decimal("100.00"))
        self.assertEqual(data['status'], VirtualCard.CardStatus.ACTIVE)

    def test_virtual_card_create_serializer_validation(self):
        """Test VirtualCardCreateSerializer validation"""
        request_mock = MagicMock()
        request_mock.user = self.user
        
        # Test valid data
        data = {'bank_account_number': '1234567890'}
        serializer = VirtualCardCreateSerializer(
            data=data, 
            context={'request': request_mock}
        )
        self.assertTrue(serializer.is_valid())

    def test_virtual_card_create_serializer_max_cards_validation(self):
        """Test validation when user has maximum cards"""
        # Create 3 virtual cards
        for i in range(3):
            VirtualCard.objects.create(
                user=self.user,
                bank_account=self.bank_account,
                card_number=f"123456789012345{i}",
                expiry_date=timezone.now() + timezone.timedelta(days=365),
                cvv=f"12{i}"
            )
        
        request_mock = MagicMock()
        request_mock.user = self.user
        
        data = {'bank_account_number': '1234567890'}
        serializer = VirtualCardCreateSerializer(
            data=data,
            context={'request': request_mock}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    @patch('core_apps.cards.serializers.generate_card_number')
    @patch('core_apps.cards.serializers.generate_cvv')
    def test_virtual_card_create_serializer_create_method(self, mock_cvv, mock_card_number):
        """Test VirtualCardCreateSerializer create method"""
        mock_card_number.return_value = "9876543210987654"
        mock_cvv.return_value = "987"
        
        validated_data = {
            'user': self.user,
            'bank_account_number': '1234567890'
        }
        
        serializer = VirtualCardCreateSerializer()
        virtual_card = serializer.create(validated_data)
        
        self.assertEqual(virtual_card.user, self.user)
        self.assertEqual(virtual_card.bank_account, self.bank_account)
        self.assertEqual(virtual_card.card_number, "9876543210987654")
        self.assertEqual(virtual_card.cvv, "987")


class VirtualCardEmailTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.bank_account = BankAccount.objects.create(
            user=self.user,
            account_number="1234567890",
            account_balance=Decimal("1000.00"),
            currency="USD"
        )
        self.virtual_card = VirtualCard.objects.create(
            user=self.user,
            bank_account=self.bank_account,
            card_number="1234567890123456",
            expiry_date=timezone.now() + timezone.timedelta(days=365),
            cvv="123"
        )

    @patch('core_apps.cards.emails.render_to_string')
    def test_send_virtual_card_topup_email_success(self, mock_render):
        """Test successful email sending for card top-up"""
        mock_render.return_value = "<html>Test email</html>"
        
        send_virtual_card_topup_email(
            self.user, 
            self.virtual_card, 
            Decimal("50.00"), 
            Decimal("150.00")
        )
        
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.subject, "Virtual Card Top-Up Confirmation")
        self.assertEqual(email.to, [self.user.email])

    @patch('core_apps.cards.emails.logger')
    @patch('core_apps.cards.emails.EmailMultiAlternatives.send')
    def test_send_virtual_card_topup_email_failure(self, mock_send, mock_logger):
        """Test email sending failure handling"""
        mock_send.side_effect = Exception("SMTP Error")
        
        send_virtual_card_topup_email(
            self.user,
            self.virtual_card,
            Decimal("50.00"),
            Decimal("150.00")
        )
        
        mock_logger.error.assert_called_once()


class VirtualCardAPITestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.bank_account = BankAccount.objects.create(
            user=self.user,
            account_number="1234567890",
            account_balance=Decimal("1000.00"),
            currency="USD"
        )
        self.virtual_card = VirtualCard.objects.create(
            user=self.user,
            bank_account=self.bank_account,
            card_number="1234567890123456",
            expiry_date=timezone.now() + timezone.timedelta(days=365),
            cvv="123",
            balance=Decimal("100.00")
        )
        self.client.force_authenticate(user=self.user)

    def test_list_virtual_cards(self):
        """Test listing virtual cards"""
        url = reverse('virtual-card-list-create')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['visa_card']), 1)

    @patch('core_apps.cards.views.VirtualCardCreateSerializer.save')
    def test_create_virtual_card_success(self, mock_save):
        """Test successful virtual card creation"""
        mock_save.return_value = self.virtual_card
        
        url = reverse('virtual-card-list-create')
        data = {'bank_account_number': '1234567890'}
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_virtual_card_max_limit(self):
        """Test creating virtual card when at maximum limit"""
        # Create 2 more cards to reach limit of 3
        for i in range(2):
            VirtualCard.objects.create(
                user=self.user,
                bank_account=self.bank_account,
                card_number=f"123456789012345{i}",
                expiry_date=timezone.now() + timezone.timedelta(days=365),
                cvv=f"12{i}"
            )
        
        url = reverse('virtual-card-list-create')
        data = {'bank_account_number': '1234567890'}
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_create_virtual_card_invalid_bank_account(self):
        """Test creating virtual card with invalid bank account"""
        url = reverse('virtual-card-list-create')
        data = {'bank_account_number': '9999999999'}
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_retrieve_virtual_card(self):
        """Test retrieving a specific virtual card"""
        url = reverse('virtual-card-detail', kwargs={'pk': self.virtual_card.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['visa_card']['card_number'], self.virtual_card.card_number)

    def test_update_virtual_card(self):
        """Test updating a virtual card"""
        url = reverse('virtual-card-detail', kwargs={'pk': self.virtual_card.pk})
        data = {'balance': '200.00'}
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.virtual_card.refresh_from_db()
        self.assertEqual(self.virtual_card.balance, Decimal('200.00'))

    def test_delete_virtual_card_with_zero_balance(self):
        """Test deleting virtual card with zero balance"""
        self.virtual_card.balance = Decimal('0.00')
        self.virtual_card.save()
        
        url = reverse('virtual-card-detail', kwargs={'pk': self.virtual_card.pk})
        response = self.client.delete(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(VirtualCard.objects.filter(pk=self.virtual_card.pk).exists())

    def test_delete_virtual_card_with_non_zero_balance(self):
        """Test deleting virtual card with non-zero balance"""
        url = reverse('virtual-card-detail', kwargs={'pk': self.virtual_card.pk})
        response = self.client.delete(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    @patch('core_apps.cards.views.send_virtual_card_topup_email')
    def test_virtual_card_topup_success(self, mock_email):
        """Test successful virtual card top-up"""
        url = reverse('virtual-card-topup', kwargs={'pk': self.virtual_card.pk})
        data = {'amount': '50.00'}
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.virtual_card.refresh_from_db()
        self.bank_account.refresh_from_db()
        
        self.assertEqual(self.virtual_card.balance, Decimal('150.00'))
        self.assertEqual(self.bank_account.account_balance, Decimal('950.00'))
        
        # Check transaction was created
        self.assertTrue(Transaction.objects.filter(user=self.user).exists())
        
        # Check email was sent
        mock_email.assert_called_once()

    def test_virtual_card_topup_no_amount(self):
        """Test virtual card top-up without amount"""
        url = reverse('virtual-card-topup', kwargs={'pk': self.virtual_card.pk})
        response = self.client.patch(url, {})
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_virtual_card_topup_invalid_amount(self):
        """Test virtual card top-up with invalid amount"""
        url = reverse('virtual-card-topup', kwargs={'pk': self.virtual_card.pk})
        data = {'amount': 'invalid'}
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_virtual_card_topup_negative_amount(self):
        """Test virtual card top-up with negative amount"""
        url = reverse('virtual-card-topup', kwargs={'pk': self.virtual_card.pk})
        data = {'amount': '-50.00'}
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_virtual_card_topup_insufficient_funds(self):
        """Test virtual card top-up with insufficient funds"""
        url = reverse('virtual-card-topup', kwargs={'pk': self.virtual_card.pk})
        data = {'amount': '2000.00'}  # More than bank account balance
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)


class VirtualCardAdminTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.bank_account = BankAccount.objects.create(
            user=self.user,
            account_number="1234567890",
            account_balance=Decimal("1000.00"),
            currency="USD"
        )
        self.virtual_card = VirtualCard.objects.create(
            user=self.user,
            bank_account=self.bank_account,
            card_number="1234567890123456",
            expiry_date=timezone.now() + timezone.timedelta(days=365),
            cvv="123",
            balance=Decimal("100.00")
        )

    def test_admin_has_delete_permission_false(self):
        """Test that admin delete permission is disabled"""
        from core_apps.cards.admin import VirtualCardAdmin
        from django.contrib.admin.sites import AdminSite
        
        admin = VirtualCardAdmin(VirtualCard, AdminSite())
        request = MagicMock()
        
        self.assertFalse(admin.has_delete_permission(request))
        self.assertFalse(admin.has_delete_permission(request, self.virtual_card))

    def test_admin_user_full_name_method(self):
        """Test admin user_full_name method"""
        from core_apps.cards.admin import VirtualCardAdmin
        from django.contrib.admin.sites import AdminSite
        
        admin = VirtualCardAdmin(VirtualCard, AdminSite())
        result = admin.user_full_name(self.virtual_card)
        
        self.assertEqual(result, self.user.full_name)

    def test_admin_bank_account_number_method(self):
        """Test admin bank_account_number method"""
        from core_apps.cards.admin import VirtualCardAdmin
        from django.contrib.admin.sites import AdminSite
        
        admin = VirtualCardAdmin(VirtualCard, AdminSite())
        result = admin.bank_account_number(self.virtual_card)
        
        self.assertEqual(result, self.bank_account.account_number)

    def test_admin_get_queryset_optimization(self):
        """Test that admin queryset uses select_related"""
        from core_apps.cards.admin import VirtualCardAdmin
        from django.contrib.admin.sites import AdminSite
        
        admin = VirtualCardAdmin(VirtualCard, AdminSite())
        request = MagicMock()
        
        queryset = admin.get_queryset(request)
        
        # Check that select_related was applied
        self.assertIn('user', queryset.query.select_related)
        self.assertIn('bank_account', queryset.query.select_related)