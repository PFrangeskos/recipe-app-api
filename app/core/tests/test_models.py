from django.test import TestCase
from django.contrib.auth import get_user_model

from core import models


def sample_user(email='test@londonappdev.com', password='testpass'):
    # create a sample user.
    return get_user_model().objects.create_user(email, password)


class ModelTests(TestCase):

    def test_create_user_with_email_successful(self):
        # Test creating a new user with an email is successful
        # print('core.m.test_create_user_with_email_successful')
        email = 'p@test.com'
        password = 'testpass123'
        user = get_user_model().objects.create_user(
            email=email,
            password=password
        )

        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))

    def test_new_user_normalized(self):
        # test the email for a new user is normalized.
        # print('core.m.test_new_user_normalized')
        email = 'test@LONDON.COM'
        user = get_user_model().objects.create_user(email, 'testpass123')

        self.assertEqual(user.email, email.lower())

    def test_new_user_invalid_email(self):
        # test creating user with no email raises error
        # print('core.m.test_new_user_invalid_email')
        with self.assertRaises(ValueError):
            get_user_model().objects.create_user(None, 'test123')

    def test_create_new_superuser(self):
        # print('core.m.test_create_new_superuser')
        # test creating a new superuser
        user = get_user_model().objects.create_superuser(
            'p@gmail.com',
            'test12'
        )

        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

    def test_tag_str(self):
        # test the tag rerpresentation.
        # print('core.m.test_tag_str')
        tag = models.Tag.objects.create(
            user=sample_user(),
            name='Vegan'
        )

        self.assertEqual(str(tag), tag.name)

    def test_ingredient_str(self):
        # Test the ingredient string representation.
        ingredient = models.Ingredient.objects.create(
            user=sample_user(),
            name='Cucumber'
        )

        self.assertEqual(str(ingredient), ingredient.name)
