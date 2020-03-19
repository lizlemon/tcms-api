DEBUG = True

ROOT_URLCONF = 'kiwitcms_kerberos.urls'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/tmp/kiwi.db.sqlite'
    }
}

if 'social_django' not in INSTALLED_APPS:   # noqa: F821
    INSTALLED_APPS.append('social_django')  # noqa: F821

if 'social_django.views.auth' not in PUBLIC_VIEWS:   # noqa: F821
    PUBLIC_VIEWS.append('social_django.views.auth')  # noqa: F821

if 'social_django.views.complete' not in PUBLIC_VIEWS:   # noqa: F821
    PUBLIC_VIEWS.append('social_django.views.complete')  # noqa: F821

SOCIAL_AUTH_URL_NAMESPACE = 'social'

SOCIAL_AUTH_PIPELINE = [
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
]

AUTHENTICATION_BACKENDS = [
    'social_auth_kerberos.backend.KerberosAuth',
    'django.contrib.auth.backends.ModelBackend',
]

SOCIAL_AUTH_KRB5_KEYTAB = '/Kiwi/application.keytab'