from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.urls import reverse

from .models import UserProfile
from .rbac import ROLE_ADMIN, ROLE_INSTRUCTOR, ROLE_MEMBER, get_user_role, user_has_group


# ── Helpers ──────────────────────────────────────────────────────────────────

def create_user(username='testuser', password='StrongPass123!', email='test@example.com'):
    user = User.objects.create_user(username=username, password=password, email=email)
    UserProfile.objects.get_or_create(user=user)
    return user


def create_instructor(username='instructor', password='StrongPass123!'):
    user = create_user(username=username, password=password, email=f'{username}@test.com')
    group, _ = Group.objects.get_or_create(name=ROLE_INSTRUCTOR)
    user.groups.add(group)
    return user


def create_admin(username='admin', password='StrongPass123!'):
    user = create_user(username=username, password=password, email=f'{username}@test.com')
    user.is_staff = True
    user.save()
    group, _ = Group.objects.get_or_create(name=ROLE_ADMIN)
    user.groups.add(group)
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


# ── RBAC: Role helpers ────────────────────────────────────────────────────────

class RBACHelperTests(TestCase):
    """Unit-test the rbac.py helper functions in isolation."""

    def test_anonymous_role(self):
        from django.contrib.auth.models import AnonymousUser
        anon = AnonymousUser()
        self.assertEqual(get_user_role(anon), 'Anonymous')
        self.assertFalse(user_has_group(anon, ROLE_MEMBER))

    def test_member_role(self):
        user = create_user(username='mem')
        self.assertEqual(get_user_role(user), 'Member')
        self.assertFalse(user_has_group(user, ROLE_INSTRUCTOR))
        self.assertFalse(user_has_group(user, ROLE_ADMIN))

    def test_instructor_role(self):
        user = create_instructor(username='inst')
        self.assertEqual(get_user_role(user), 'Instructor')
        self.assertTrue(user_has_group(user, ROLE_INSTRUCTOR))
        self.assertFalse(user_has_group(user, ROLE_ADMIN))

    def test_admin_role(self):
        user = create_admin(username='adm')
        self.assertEqual(get_user_role(user), 'Admin')
        # Staff users pass all group checks via user_has_group.
        self.assertTrue(user_has_group(user, ROLE_INSTRUCTOR))
        self.assertTrue(user_has_group(user, ROLE_ADMIN))


# ── RBAC: Instructor panel access ────────────────────────────────────────────

class InstructorPanelAccessTests(TestCase):

    def setUp(self):
        self.url = reverse('kayigamba_david:instructor_panel')
        self.member     = create_user(username='mem')
        self.instructor = create_instructor(username='inst')
        self.admin      = create_admin(username='adm')

    def test_anonymous_redirected_to_login(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, f"{reverse('kayigamba_david:login')}?next={self.url}")

    def test_member_gets_403(self):
        self.client.login(username='mem', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_instructor_can_access(self):
        self.client.login(username='inst', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_admin_can_access_instructor_panel(self):
        # Admin (staff) passes the group_required check too.
        self.client.login(username='adm', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_instructor_panel_lists_users(self):
        self.client.login(username='inst', password='StrongPass123!')
        response = self.client.get(self.url)
        # mem user should appear in the table.
        self.assertContains(response, 'mem')


# ── RBAC: Admin panel access ──────────────────────────────────────────────────

class AdminPanelAccessTests(TestCase):

    def setUp(self):
        self.url = reverse('kayigamba_david:admin_panel')
        self.member     = create_user(username='mem')
        self.instructor = create_instructor(username='inst')
        self.admin      = create_admin(username='adm')

    def test_anonymous_redirected_to_login(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, f"{reverse('kayigamba_david:login')}?next={self.url}")

    def test_member_gets_403(self):
        self.client.login(username='mem', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_instructor_gets_403(self):
        # Instructor role must NOT access the admin panel — privilege separation.
        self.client.login(username='inst', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_admin_can_access(self):
        self.client.login(username='adm', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_admin_panel_shows_all_users(self):
        self.client.login(username='adm', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertContains(response, 'mem')
        self.assertContains(response, 'inst')


# ── RBAC: Privilege escalation prevention ────────────────────────────────────

class PrivilegeEscalationTests(TestCase):
    """
    Verify that no role can access resources above its level,
    even by direct URL manipulation.
    """

    def setUp(self):
        self.member     = create_user(username='mem')
        self.instructor = create_instructor(username='inst')

    def test_member_cannot_reach_instructor_panel_by_url(self):
        self.client.login(username='mem', password='StrongPass123!')
        response = self.client.get('/auth/instructor/')
        self.assertEqual(response.status_code, 403)

    def test_member_cannot_reach_admin_panel_by_url(self):
        self.client.login(username='mem', password='StrongPass123!')
        response = self.client.get('/auth/admin-panel/')
        self.assertEqual(response.status_code, 403)

    def test_instructor_cannot_reach_admin_panel_by_url(self):
        self.client.login(username='inst', password='StrongPass123!')
        response = self.client.get('/auth/admin-panel/')
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_cannot_reach_any_protected_url(self):
        for path in ['/auth/dashboard/', '/auth/instructor/', '/auth/admin-panel/']:
            with self.subTest(path=path):
                response = self.client.get(path)
                # Must redirect to login, never expose data.
                self.assertIn(response.status_code, [302, 403])
                self.assertNotEqual(response.status_code, 200)


# ── RBAC: Signal — auto Member group assignment ───────────────────────────────

class AutoMemberGroupTests(TestCase):
    """Verify that new users are automatically placed in the Member group."""

    def test_new_user_assigned_to_member_group(self):
        user = create_user(username='fresh')
        self.assertTrue(
            user.groups.filter(name=ROLE_MEMBER).exists(),
            'New user must be auto-assigned to the Member group by the post_save signal.',
        )

    def test_registration_assigns_member_group(self):
        """End-to-end: registering via the web form auto-assigns the Member group."""
        self.client.post(reverse('kayigamba_david:register'), {
            'username':   'webuser',
            'email':      'webuser@test.com',
            'password1':  'StrongPass123!',
            'password2':  'StrongPass123!',
        })
        user = User.objects.get(username='webuser')
        self.assertTrue(user.groups.filter(name=ROLE_MEMBER).exists())
