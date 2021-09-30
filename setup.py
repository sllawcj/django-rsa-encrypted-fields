from __future__ import print_function
from setuptools import setup

setup(
    name='django-fernet-encrypted-fields',
    description=(
        'This is inspired by django-encrypted-fields.'
    ),
    url='http://github.com/frgmt/django-fernet-encrypted-fields/',
    license='MIT',
    author='fragment.co.jp',
    author_email='info@fragment.co.jp',
    packages=['encrypted_fields'],
    version='0.0.1',
    install_requires=[
        'Django>=2.2',
        'cryptography>=35.0.0',
    ],
)