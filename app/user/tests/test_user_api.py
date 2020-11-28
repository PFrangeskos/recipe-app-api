from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient
from rest_framework import status


CREATE_USER_URL = reverse('user:create')
TOKEN_URL = reverse('user:token')
ME_URL = reverse('user:me')


def create_user(**params):
    return get_user_model().objects.create_user(**params)


class PublicUserApiTests(TestCase):
    # test the users API (public).

    def setUp(self):
        self.client = APIClient()

    def test_create_valid_user_success(self):
        # test creating user with valid payload is successful.
        # print('user.test_create_valid_user_success')
        payload = {
            'email': 'test@londonappdev.com',
            'password': 'testpass',
            'name': 'Test Name'
        }
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(**res.data)
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)

    def test_user_exists(self):
        # test creating a user that already exists fails.
        # print('user.test_user_exists')
        payload = {
            'email': 'test@londonappdev.com',
            'password': 'testpass'
        }
        create_user(**payload)

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short(self):
        # test that the password must be more than 5 characters.
        # print('user.test_password_too_short')
        payload = {
            'email': 'test@londonappdev.com',
            'password': 'pw',
            'name': 'Test'
        }
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)

    def test_create_token_for_user(self):
        # test that a token is created for the user.
        # print('user.test_create_token_for_user')
        payload = {'email': 'test@londonappdev.com', 'password': 'testpass'}
        create_user(**payload)
        res = self.client.post(TOKEN_URL, payload)

        self.assertIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_create_token_invalid_credentials(self):
        # test that token is not created if invalid credentials are given.
        # print('user.test_create_token_invalid_credentials')
        create_user(email='test@londonappdev', password='testpass')
        payload = {'email': 'test@londonappdev.com', 'password': 'wrong'}
        res = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_no_user(self):
        # test that token is not created if user doesn't exists.
        # create_user(email='test@londonappdev', password='testpass')
        # print('user.test_create_token_no_user')
        payload = {'email': 'test@londonappdev.com', 'password': 'testpass'}
        res = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_missing_fields(self):
        # test that email and password are required.
        # print('user.test_create_token_missing_fields')
        res = self.client.post(TOKEN_URL, {'email': 'one', 'password': ''})

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def Χtest_retrieve_user_unauthorized(self):
        # Test that authentication required for users
        # print('user.test_retrieve_user_unauthorized')
        res = self.client.get(ME_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateUserApiTest(TestCase):
    # test API requests that require authentication.

    def setUp(self):
        self.user = create_user(
            email='test@londonappdev.com',
            password='testpass',
            name='name'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_retrieve_profile_success(self):
        # test retrieving profile for logged in used.
        # print('user.test_retrieve_profile_success')
        res = self.client.get(ME_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, {
            'name': self.user.name,
            'email': self.user.email
        })

    def test_post_me_not_allowed(self):
        # test that POST is not allowed on the me url.
        # print('user.test_post_me_not_allowed')
        res = self.client.post(ME_URL, {})

        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_user_profile(self):
        # test updating the user profile for authenticated user.
        # print('user.test_update_user_profile')
        payload = {'name': 'new name', 'password': 'newpass'}

        res = self.client.patch(ME_URL, payload)

        self.user.refresh_from_db()
        self.assertEqual(self.user.name, payload['name'])
        self.assertTrue(self.user.check_password(payload['password']))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
