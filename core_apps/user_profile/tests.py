import base64
import tempfile
from datetime import date, datetime
from decimal import Decimal
from io import BytesIO
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from PIL import Image
from rest_framework import status
from rest_framework.test import APITestCase

from core_apps.common.models import ContentView
from core_apps.user_profile.models import NextOfKin, Profile
from core_apps.user_profile.serializers import NextOfKinSerializer, ProfileSerializer
from core_apps.user_profile.tasks import upload_photos_to_cloudinary

User = get_user_model()


class ProfileModelTest(TestCase):
    """Test cases for Profile model"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.profile = Profile.objects.get(user=self.user)

    def test_profile_creation_via_signal(self):
        """Test that profile is automatically created when user is created"""
        new_user = User.objects.create_user(
            email="newuser@example.com",
            first_name="Jane",
            last_name="Smith",
            password="testpass123"
        )
        self.assertTrue(hasattr(new_user, 'profile'))
        self.assertIsInstance(new_user.profile, Profile)

    def test_profile_str_representation(self):
        """Test string representation of profile"""
        expected = f"{self.profile.title} {self.user.first_name}'s Profile"
        self.assertEqual(str(self.profile), expected)

    def test_profile_defaults(self):
        """Test profile default values"""
        self.assertEqual(self.profile.title, Profile.Salutation.MR)
        self.assertEqual(self.profile.gender, Profile.Gender.MALE)
        self.assertEqual(self.profile.marital_status, Profile.MaritalStatus.UNKNOWN)
        self.assertEqual(self.profile.employment_status, Profile.EmploymentStatus.SELF_EMPLOYED)

    def test_clean_method_valid_dates(self):
        """Test clean method with valid dates"""
        self.profile.id_issue_date = date(2020, 1, 1)
        self.profile.id_expiry_date = date(2025, 1, 1)
        try:
            self.profile.clean()
        except ValidationError:
            self.fail("clean() raised ValidationError unexpectedly")

    def test_clean_method_invalid_dates(self):
        """Test clean method with invalid dates (expiry before issue)"""
        self.profile.id_issue_date = date(2025, 1, 1)
        self.profile.id_expiry_date = date(2020, 1, 1)
        with self.assertRaises(ValidationError) as context:
            self.profile.clean()
        self.assertIn("ID expiry date must come after issue date", str(context.exception))

    def test_is_complete_with_next_of_kin_incomplete(self):
        """Test is_complete_with_next_of_kin method when profile is incomplete"""
        self.assertFalse(self.profile.is_complete_with_next_of_kin())

    def test_is_complete_with_next_of_kin_complete(self):
        """Test is_complete_with_next_of_kin method when profile is complete"""
        # Set all required fields
        self.profile.title = Profile.Salutation.MR
        self.profile.gender = Profile.Gender.MALE
        self.profile.date_of_birth = date(1990, 1, 1)
        self.profile.country_of_birth = "US"
        self.profile.place_of_birth = "New York"
        self.profile.marital_status = Profile.MaritalStatus.SINGLE
        self.profile.means_of_identification = Profile.IdentificationMeans.DRIVERS_LICENSE
        self.profile.id_issue_date = date(2020, 1, 1)
        self.profile.id_expiry_date = date(2025, 1, 1)
        self.profile.nationality = "American"
        self.profile.phone_number = "+12345678901"
        self.profile.address = "123 Main St"
        self.profile.city = "New York"
        self.profile.country = "US"
        self.profile.employment_status = Profile.EmploymentStatus.EMPLOYED
        self.profile.photo = "test_photo"
        self.profile.id_photo = "test_id_photo"
        self.profile.signature_photo = "test_signature"
        self.profile.save()

        # Create next of kin
        NextOfKin.objects.create(
            profile=self.profile,
            title=NextOfKin.Salutation.MRS,
            first_name="Jane",
            last_name="Doe",
            date_of_birth=date(1985, 1, 1),
            gender=NextOfKin.Gender.FEMALE,
            relationship="Spouse",
            email_address="jane@example.com",
            phone_number="+12345678902",
            address="123 Main St",
            city="New York",
            country="US",
            is_primary=True
        )

        self.assertTrue(self.profile.is_complete_with_next_of_kin())


class NextOfKinModelTest(TestCase):
    """Test cases for NextOfKin model"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.profile = Profile.objects.get(user=self.user)

    def test_next_of_kin_creation(self):
        """Test NextOfKin model creation"""
        next_of_kin = NextOfKin.objects.create(
            profile=self.profile,
            title=NextOfKin.Salutation.MRS,
            first_name="Jane",
            last_name="Doe",
            date_of_birth=date(1985, 1, 1),
            gender=NextOfKin.Gender.FEMALE,
            relationship="Spouse",
            email_address="jane@example.com",
            phone_number="+12345678902",
            address="123 Main St",
            city="New York",
            country="US",
            is_primary=True
        )
        self.assertEqual(next_of_kin.profile, self.profile)
        self.assertEqual(next_of_kin.first_name, "Jane")
        self.assertTrue(next_of_kin.is_primary)

    def test_next_of_kin_str_representation(self):
        """Test string representation of NextOfKin"""
        next_of_kin = NextOfKin.objects.create(
            profile=self.profile,
            title=NextOfKin.Salutation.MRS,
            first_name="Jane",
            last_name="Doe",
            date_of_birth=date(1985, 1, 1),
            gender=NextOfKin.Gender.FEMALE,
            relationship="Spouse",
            email_address="jane@example.com",
            phone_number="+12345678902",
            address="123 Main St",
            city="New York",
            country="US",
            is_primary=True
        )
        expected = f"Jane Doe - Next of Kin for {self.profile.user.full_name}"
        self.assertEqual(str(next_of_kin), expected)

    def test_only_one_primary_next_of_kin_constraint(self):
        """Test that only one primary next of kin is allowed per profile"""
        # Create first primary next of kin
        NextOfKin.objects.create(
            profile=self.profile,
            title=NextOfKin.Salutation.MRS,
            first_name="Jane",
            last_name="Doe",
            date_of_birth=date(1985, 1, 1),
            gender=NextOfKin.Gender.FEMALE,
            relationship="Spouse",
            email_address="jane@example.com",
            phone_number="+12345678902",
            address="123 Main St",
            city="New York",
            country="US",
            is_primary=True
        )

        # Try to create second primary next of kin
        second_kin = NextOfKin(
            profile=self.profile,
            title=NextOfKin.Salutation.MR,
            first_name="Bob",
            last_name="Smith",
            date_of_birth=date(1980, 1, 1),
            gender=NextOfKin.Gender.MALE,
            relationship="Brother",
            email_address="bob@example.com",
            phone_number="+12345678903",
            address="456 Oak St",
            city="Boston",
            country="US",
            is_primary=True
        )

        with self.assertRaises(ValidationError) as context:
            second_kin.clean()
        self.assertIn("There can only be one primary next of kin", str(context.exception))


class ProfileSerializerTest(TestCase):
    """Test cases for ProfileSerializer"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.profile = Profile.objects.get(user=self.user)

    def test_profile_serializer_fields(self):
        """Test ProfileSerializer contains expected fields"""
        serializer = ProfileSerializer(instance=self.profile)
        expected_fields = {
            'id', 'first_name', 'middle_name', 'last_name', 'username', 'id_no',
            'email', 'full_name', 'date_joined', 'title', 'gender', 'date_of_birth',
            'country_of_birth', 'place_of_birth', 'marital_status', 'means_of_identification',
            'id_issue_date', 'id_expiry_date', 'passport_number', 'nationality',
            'phone_number', 'address', 'city', 'country', 'employment_status',
            'employer_name', 'annual_income', 'date_of_employment', 'employer_address',
            'employer_city', 'employer_state', 'next_of_kin', 'created_at', 'updated_at',
            'photo', 'photo_url', 'id_photo', 'id_photo_url', 'signature_photo',
            'signature_photo_url', 'view_count'
        }
        self.assertEqual(set(serializer.data.keys()), expected_fields)

    def test_profile_serializer_validation_invalid_dates(self):
        """Test ProfileSerializer validation with invalid dates"""
        data = {
            'id_issue_date': '2025-01-01',
            'id_expiry_date': '2020-01-01'
        }
        serializer = ProfileSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('id_expiry_date', serializer.errors)

    def test_profile_serializer_validation_valid_dates(self):
        """Test ProfileSerializer validation with valid dates"""
        data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'id_issue_date': '2020-01-01',
            'id_expiry_date': '2025-01-01'
        }
        serializer = ProfileSerializer(data=data, partial=True)
        self.assertTrue(serializer.is_valid())

    @patch('core_apps.user_profile.serializers.upload_photos_to_cloudinary.delay')
    def test_profile_serializer_update_with_photo(self, mock_upload):
        """Test ProfileSerializer update with photo upload"""
        # Create a simple test image
        image = Image.new('RGB', (100, 100), color='red')
        temp_file = BytesIO()
        image.save(temp_file, format='JPEG')
        temp_file.seek(0)
        
        photo = SimpleUploadedFile(
            "test_photo.jpg", 
            temp_file.getvalue(), 
            content_type="image/jpeg"
        )
        
        data = {
            'first_name': 'Updated John',
            'photo': photo
        }
        
        serializer = ProfileSerializer(instance=self.profile, data=data, partial=True)
        self.assertTrue(serializer.is_valid())
        
        updated_profile = serializer.save()
        self.assertEqual(updated_profile.user.first_name, 'Updated John')
        mock_upload.assert_called_once()


class NextOfKinSerializerTest(TestCase):
    """Test cases for NextOfKinSerializer"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.profile = Profile.objects.get(user=self.user)

    def test_next_of_kin_serializer_creation(self):
        """Test NextOfKinSerializer creation"""
        data = {
            'title': NextOfKin.Salutation.MRS,
            'first_name': 'Jane',
            'last_name': 'Doe',
            'date_of_birth': '1985-01-01',
            'gender': NextOfKin.Gender.FEMALE,
            'relationship': 'Spouse',
            'email_address': 'jane@example.com',
            'phone_number': '+12345678902',
            'address': '123 Main St',
            'city': 'New York',
            'country': 'US',
            'is_primary': True
        }
        
        serializer = NextOfKinSerializer(data=data, context={'profile': self.profile})
        self.assertTrue(serializer.is_valid())
        
        next_of_kin = serializer.save()
        self.assertEqual(next_of_kin.profile, self.profile)
        self.assertEqual(next_of_kin.first_name, 'Jane')

    def test_next_of_kin_serializer_missing_profile_context(self):
        """Test NextOfKinSerializer without profile context"""
        data = {
            'title': NextOfKin.Salutation.MRS,
            'first_name': 'Jane',
            'last_name': 'Doe',
            'date_of_birth': '1985-01-01',
            'gender': NextOfKin.Gender.FEMALE,
            'relationship': 'Spouse',
            'email_address': 'jane@example.com',
            'phone_number': '+12345678902',
            'address': '123 Main St',
            'city': 'New York',
            'country': 'US',
            'is_primary': True
        }
        
        serializer = NextOfKinSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        with self.assertRaises(Exception):
            serializer.save()


class ProfileAPIViewTest(APITestCase):
    """Test cases for Profile API views"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.profile = Profile.objects.get(user=self.user)
        self.client.force_authenticate(user=self.user)

    def test_profile_detail_get(self):
        """Test retrieving profile details"""
        url = reverse('profile_detail')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)

    def test_profile_detail_update(self):
        """Test updating profile"""
        url = reverse('profile_detail')
        data = {
            'first_name': 'Updated John',
            'nationality': 'American'
        }
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated John')
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.nationality, 'American')

    def test_profile_view_count_increment(self):
        """Test that profile view count increments"""
        url = reverse('profile_detail')
        
        # First request
        self.client.get(url)
        
        # Second request
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check ContentView was created
        content_type = ContentType.objects.get_for_model(Profile)
        view_count = ContentView.objects.filter(
            content_type=content_type,
            object_id=self.profile.id
        ).count()
        self.assertEqual(view_count, 1)  # Should be 1 due to update_or_create


class NextOfKinAPIViewTest(APITestCase):
    """Test cases for NextOfKin API views"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.profile = Profile.objects.get(user=self.user)
        self.client.force_authenticate(user=self.user)

    def test_next_of_kin_list_empty(self):
        """Test listing next of kin when none exist"""
        url = reverse('next-of-kin-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    def test_next_of_kin_create(self):
        """Test creating next of kin"""
        url = reverse('next-of-kin-list')
        data = {
            'title': 'mrs',
            'first_name': 'Jane',
            'last_name': 'Doe',
            'date_of_birth': '1985-01-01',
            'gender': 'female',
            'relationship': 'Spouse',
            'email_address': 'jane@example.com',
            'phone_number': '+12345678902',
            'address': '123 Main St',
            'city': 'New York',
            'country': 'US',
            'is_primary': True
        }
        
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NextOfKin.objects.count(), 1)
        
        next_of_kin = NextOfKin.objects.first()
        self.assertEqual(next_of_kin.first_name, 'Jane')
        self.assertEqual(next_of_kin.profile, self.profile)

    def test_next_of_kin_detail_get(self):
        """Test retrieving specific next of kin"""
        next_of_kin = NextOfKin.objects.create(
            profile=self.profile,
            title=NextOfKin.Salutation.MRS,
            first_name="Jane",
            last_name="Doe",
            date_of_birth=date(1985, 1, 1),
            gender=NextOfKin.Gender.FEMALE,
            relationship="Spouse",
            email_address="jane@example.com",
            phone_number="+12345678902",
            address="123 Main St",
            city="New York",
            country="US",
            is_primary=True
        )
        
        url = reverse('next-of-kin-detail', kwargs={'pk': next_of_kin.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Jane')

    def test_next_of_kin_detail_update(self):
        """Test updating specific next of kin"""
        next_of_kin = NextOfKin.objects.create(
            profile=self.profile,
            title=NextOfKin.Salutation.MRS,
            first_name="Jane",
            last_name="Doe",
            date_of_birth=date(1985, 1, 1),
            gender=NextOfKin.Gender.FEMALE,
            relationship="Spouse",
            email_address="jane@example.com",
            phone_number="+12345678902",
            address="123 Main St",
            city="New York",
            country="US",
            is_primary=True
        )
        
        url = reverse('next-of-kin-detail', kwargs={'pk': next_of_kin.pk})
        data = {'first_name': 'Updated Jane'}
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        next_of_kin.refresh_from_db()
        self.assertEqual(next_of_kin.first_name, 'Updated Jane')

    def test_next_of_kin_detail_delete(self):
        """Test deleting specific next of kin"""
        next_of_kin = NextOfKin.objects.create(
            profile=self.profile,
            title=NextOfKin.Salutation.MRS,
            first_name="Jane",
            last_name="Doe",
            date_of_birth=date(1985, 1, 1),
            gender=NextOfKin.Gender.FEMALE,
            relationship="Spouse",
            email_address="jane@example.com",
            phone_number="+12345678902",
            address="123 Main St",
            city="New York",
            country="US",
            is_primary=True
        )
        
        url = reverse('next-of-kin-detail', kwargs={'pk': next_of_kin.pk})
        response = self.client.delete(url)
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(NextOfKin.objects.count(), 0)


class TasksTest(TestCase):
    """Test cases for Celery tasks"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            password="testpass123"
        )
        self.profile = Profile.objects.get(user=self.user)

    @patch('cloudinary.uploader.upload')
    @patch('core_apps.user_profile.tasks.logger')
    def test_upload_photos_to_cloudinary_base64(self, mock_logger, mock_upload):
        """Test uploading photos to cloudinary with base64 data"""
        mock_upload.return_value = {
            'public_id': 'test_public_id',
            'url': 'https://cloudinary.com/test.jpg'
        }
        
        # Create test image data
        image = Image.new('RGB', (100, 100), color='red')
        temp_file = BytesIO()
        image.save(temp_file, format='JPEG')
        image_data = base64.b64encode(temp_file.getvalue()).decode('utf-8')
        
        photos = {
            'photo': {
                'type': 'base64',
                'data': image_data
            }
        }
        
        upload_photos_to_cloudinary(str(self.profile.id), photos)
        
        mock_upload.assert_called_once()
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.photo, 'test_public_id')
        self.assertEqual(self.profile.photo_url, 'https://cloudinary.com/test.jpg')
        mock_logger.info.assert_called_once()

    @patch('cloudinary.uploader.upload')
    @patch('core_apps.user_profile.tasks.logger')
    def test_upload_photos_to_cloudinary_error_handling(self, mock_logger, mock_upload):
        """Test error handling in upload_photos_to_cloudinary task"""
        mock_upload.side_effect = Exception("Upload failed")
        
        photos = {
            'photo': {
                'type': 'base64',
                'data': 'invalid_base64_data'
            }
        }
        
        upload_photos_to_cloudinary(str(self.profile.id), photos)
        
        mock_logger.error.assert_called_once()


class SignalsTest(TestCase):
    """Test cases for Django signals"""

    @patch('core_apps.user_profile.signals.logger')
    def test_create_user_profile_signal(self, mock_logger):
        """Test that profile is created when user is created"""
        user = User.objects.create_user(
            email="newuser@example.com",
            first_name="New",
            last_name="User",
            password="testpass123"
        )
        
        self.assertTrue(hasattr(user, 'profile'))
        self.assertIsInstance(user.profile, Profile)
        mock_logger.info.assert_called_once_with(f"Profile created for New User")

    def test_save_user_profile_signal(self):
        """Test that profile is saved when user is saved"""
        user = User.objects.create_user(
            email="testuser@example.com",
            first_name="Test",
            last_name="User",
            password="testpass123"
        )
        
        original_updated_at = user.profile.updated_at
        
        # Update user to trigger signal
        user.first_name = "Updated Test"
        user.save()
        
        user.profile.refresh_from_db()
        self.assertGreater(user.profile.updated_at, original_updated_at)