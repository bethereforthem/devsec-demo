"""
Management command: create RBAC groups and assign permissions.

Run this once after initial migration, before seed_users:
    python manage.py setup_roles

Role → Group → Permissions mapping
------------------------------------
Member      | Member     | (none — @login_required is sufficient)
Instructor  | Instructor | can_view_user_list, can_access_instructor_panel
Admin       | Admin      | all custom permissions (users also need is_staff=True)
"""
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand

from kayigamba_david.models import UserProfile

# Permissions assigned per group.
# Keys are group names; values are lists of UserProfile permission codenames.
ROLE_PERMISSIONS = {
    'Member': [],
    'Instructor': [
        'can_view_user_list',
        'can_access_instructor_panel',
    ],
    'Admin': [
        'can_view_user_list',
        'can_access_instructor_panel',
        'can_access_admin_panel',
    ],
}


class Command(BaseCommand):
    help = 'Create RBAC groups (Member, Instructor, Admin) and assign permissions.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING('Setting up RBAC roles...\n'))

        ct = ContentType.objects.get_for_model(UserProfile)

        for group_name, codenames in ROLE_PERMISSIONS.items():
            group, created = Group.objects.get_or_create(name=group_name)
            status = self.style.SUCCESS('created') if created else 'exists'
            self.stdout.write(f'  Group "{group_name}" — {status}')

            for codename in codenames:
                try:
                    perm = Permission.objects.get(content_type=ct, codename=codename)
                    group.permissions.add(perm)
                    self.stdout.write(f'    + permission: {codename}')
                except Permission.DoesNotExist:
                    self.stdout.write(self.style.ERROR(
                        f'    ! Permission "{codename}" not found. '
                        'Did you run migrate first?'
                    ))

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('RBAC setup complete.'))
        self.stdout.write(
            'Next: run "python manage.py seed_users --reset" '
            'to assign users to groups.'
        )
