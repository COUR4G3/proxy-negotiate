import os
import re
import subprocess

from setuptools import setup

from proxy_negotiate import __version__ as version

def get_description():
    description = open('README.rst').read()
    try:
        description += '\n\n' + open('docs/changelog.rst').read()
    except IOError:
        pass
    return description

setup(
    name='Proxy-Negotiate',
    version=version,
    url='https://github.com/cour4g3/proxy-negotiate',
    license='MIT',
    author='Michael de Villiers',
    author_email='michael@cour4g3.me',
    description='HTTP Negotiate proxy authentication support for applications.',
    long_description=get_description(),
    py_modules=['proxy_negotiate'],
    platforms='any',
    install_requires=[
        'gssapi',
        'gevent',
    ],
    scripts=[
        'nc-negotiate',
        'proxy-negotiate',
    ],
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Security',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Utilities',
    ]
)
