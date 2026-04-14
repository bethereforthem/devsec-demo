"""
Management command: seed 5 demo users for testing/demonstration.

Usage:
    python manage.py seed_users
    python manage.py seed_users --reset   # delete all non-superuser accounts first
"""
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from kayigamba_david.models import UserProfile

SEED_PASSWORD = 'pass@123'

SEED_USERS = [
    {
        'username':   'alice_kay',
        'first_name': 'Alice',
        'last_name':  'Kayitesi',
        'email':      'alice@uas.dev',
        'bio':        'Full-stack developer with a passion for clean code and web security.',
    },
    {
        'username':   'bob_muk',
        'first_name': 'Bob',
        'last_name':  'Mukama',
        'email':      'bob@uas.dev',
        'bio':        'Backend engineer specialising in Django and REST APIs.',
    },
    {
        'username':   'claire_nd',
        'first_name': 'Claire',
        'last_name':  'Ndinganiye',
        'email':      'claire@uas.dev',
        'bio':        'Security researcher interested in authentication protocols.',
    },
    {
        'username':   'david_kay',
        'first_name': 'David',
        'last_name':  'Kayigamba',
        'email':      'david@uas.dev',
        'bio':        'Project author — Level 3 Web Security, Semester II.',
        'is_staff':   True,   # demo admin-lite user
    },
    {
        'username':   'eve_nk',
        'first_name': 'Eve',
        'last_name':  'Nkurunziza',
        'email':      'eve@uas.dev',
        'bio':        'UI/UX designer who loves Django templates.',
    },
]


class Command(BaseCommand):
    help = 'Seed 5 demo users with password "pass@123"'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete all existing non-superuser accounts before seeding.',
        )

    def handle(self, *args, **options):
        if options['reset']:
            deleted, _ = User.objects.filter(is_superuser=False).delete()
            self.stdout.write(self.style.WARNING(f'  Removed {deleted} existing user(s).'))

        created_count = 0
        skipped_count = 0

        for data in SEED_USERS:
            username = data['username']
            if User.objects.filter(username=username).exists():
                self.stdout.write(f'  [skip]    {username} already exists')
                skipped_count += 1
                continue

            user = User.objects.create_user(
                username=username,
                password=SEED_PASSWORD,
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                is_staff=data.get('is_staff', False),
            )
            UserProfile.objects.create(user=user, bio=data.get('bio', ''))
            self.stdout.write(self.style.SUCCESS(
                f'  [created] {username} ({data["first_name"]} {data["last_name"]}) — {data["email"]}'
            ))
            created_count += 1

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS(
            f'Done. {created_count} user(s) created, {skipped_count} skipped.'
        ))
        self.stdout.write(f'  Password for all new users: {SEED_PASSWORD}')
