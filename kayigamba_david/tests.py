from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from .models import UserProfile


# ── Helpers ──────────────────────────────────────────────────────────────────

def create_user(username='testuser', password='StrongPass123!', email='test@example.com'):
    user = User.objects.create_user(username=username, password=password, email=email)
    UserProfile.objects.create(user=user)
    return user


# ── Registration ──────────────────────────────────────────────────────────────

class RegistrationTests(TestCase):
    url = reverse_lazy = None  # resolved in setUp

    def setUp(self):
        self.url = reverse('kayigamba_david:register')

    def test_register_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Register')

    def test_successful_registration(self):
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        response = self.client.post(self.url, data)
        # Should redirect to dashboard after auto-login.
        self.assertRedirects(response, reverse('kayigamba_david:dashboard'))
        self.assertTrue(User.objects.filter(username='newuser').exists())
        # Profile auto-created.
        user = User.objects.get(username='newuser')
        self.assertTrue(UserProfile.objects.filter(user=user).exists())

    def test_registration_password_mismatch(self):
        data = {
            'username': 'baduser',
            'email': 'bad@example.com',
            'password1': 'StrongPass123!',
            'password2': 'WrongPass456!',
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context['form'], 'password2', 'Passwords do not match.')

    def test_registration_duplicate_username(self):
        create_user(username='taken')
        data = {
            'username': 'taken',
            'email': 'other@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        # Django's built-in uniqueness error on username field.
        self.assertContains(response, 'already exists')

    def test_registration_duplicate_email(self):
        create_user(email='used@example.com')
        data = {
            'username': 'anotheruser',
            'email': 'used@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context['form'], 'email', 'A user with this email already exists.')

    def test_authenticated_user_redirected_from_register(self):
        create_user()
        self.client.login(username='testuser', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertRedirects(response, reverse('kayigamba_david:dashboard'))


# ── Login / Logout ────────────────────────────────────────────────────────────

class LoginTests(TestCase):

    def setUp(self):
        self.url = reverse('kayigamba_david:login')
        self.user = create_user()

    def test_login_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_successful_login(self):
        response = self.client.post(self.url, {
            'username': 'testuser',
            'password': 'StrongPass123!',
        })
        self.assertRedirects(response, reverse('kayigamba_david:dashboard'))
        # Session should contain _auth_user_id.
        self.assertIn('_auth_user_id', self.client.session)

    def test_invalid_credentials(self):
        response = self.client.post(self.url, {
            'username': 'testuser',
            'password': 'WrongPassword!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)
        # AuthenticationForm returns a non-field error for invalid creds.
        self.assertTrue(response.context['form'].errors)

    def test_nonexistent_user(self):
        response = self.client.post(self.url, {
            'username': 'ghost',
            'password': 'StrongPass123!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_authenticated_user_redirected_from_login(self):
        self.client.login(username='testuser', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertRedirects(response, reverse('kayigamba_david:dashboard'))


class LogoutTests(TestCase):

    def setUp(self):
        self.url = reverse('kayigamba_david:logout')
        self.user = create_user()
        self.client.login(username='testuser', password='StrongPass123!')

    def test_logout_get_shows_confirmation(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Sign out')

    def test_logout_post_logs_out(self):
        response = self.client.post(self.url)
        self.assertRedirects(response, reverse('kayigamba_david:login'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_logout_requires_login(self):
        self.client.logout()
        response = self.client.post(self.url)
        # Should redirect to login.
        self.assertRedirects(response, f"{reverse('kayigamba_david:login')}?next={self.url}")


# ── Access Control ────────────────────────────────────────────────────────────

class AccessControlTests(TestCase):

    def setUp(self):
        self.user = create_user()
        self.protected_urls = [
            reverse('kayigamba_david:dashboard'),
            reverse('kayigamba_david:profile'),
            reverse('kayigamba_david:change_password'),
        ]

    def test_unauthenticated_redirected_from_protected_views(self):
        for url in self.protected_urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertRedirects(
                    response,
                    f"{reverse('kayigamba_david:login')}?next={url}",
                )

    def test_authenticated_can_access_protected_views(self):
        self.client.login(username='testuser', password='StrongPass123!')
        for url in self.protected_urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardTests(TestCase):

    def setUp(self):
        self.user = create_user(username='dave', email='dave@example.com')
        self.client.login(username='dave', password='StrongPass123!')

    def test_dashboard_shows_username(self):
        response = self.client.get(reverse('kayigamba_david:dashboard'))
        self.assertContains(response, 'dave')


# ── Profile ───────────────────────────────────────────────────────────────────

class ProfileTests(TestCase):

    def setUp(self):
        self.user = create_user()
        self.client.login(username='testuser', password='StrongPass123!')
        self.url = reverse('kayigamba_david:profile')

    def test_profile_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_profile_update(self):
        response = self.client.post(self.url, {
            'first_name': 'David',
            'last_name': 'Kay',
            'email': 'updated@example.com',
            'bio': 'Hello world',
        })
        self.assertRedirects(response, self.url)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'David')
        self.assertEqual(self.user.email, 'updated@example.com')
        self.assertEqual(self.user.profile.bio, 'Hello world')


# ── Password Change ───────────────────────────────────────────────────────────

class PasswordChangeTests(TestCase):

    def setUp(self):
        self.user = create_user()
        self.client.login(username='testuser', password='StrongPass123!')
        self.url = reverse('kayigamba_david:change_password')

    def test_change_password_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_successful_password_change(self):
        response = self.client.post(self.url, {
            'old_password': 'StrongPass123!',
            'new_password1': 'NewStrongPass456!',
            'new_password2': 'NewStrongPass456!',
        })
        self.assertRedirects(response, reverse('kayigamba_david:profile'))
        # User must still be logged in (session hash updated).
        self.assertIn('_auth_user_id', self.client.session)
        # New password works.
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewStrongPass456!'))

    def test_wrong_old_password_rejected(self):
        response = self.client.post(self.url, {
            'old_password': 'WrongOldPass!',
            'new_password1': 'NewStrongPass456!',
            'new_password2': 'NewStrongPass456!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())

    def test_mismatched_new_passwords_rejected(self):
        response = self.client.post(self.url, {
            'old_password': 'StrongPass123!',
            'new_password1': 'NewStrongPass456!',
            'new_password2': 'DifferentPass789!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())
