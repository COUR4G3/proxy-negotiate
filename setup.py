import os
import re

from setuptools import setup

def get_version():
    pattern = re.compile(r'__version__\s+=\s+[\'\"](.*)[\'\"]')
    with open('proxy_negotiate.py', 'r') as lines:
        for line in lines:
            match = re.search(pattern, line)
            if match:
                return match.groups()[0].strip()
    raise Exception('Cannot find version')

setup(
    name='Proxy-Negotiate',
    version=get_version(),
    url='https://github.com/cour4g3/proxy-negotiate',
    license='MIT',
    author='Michael de Villiers',
    author_email='twistedcomplexity@gmail.com',
    description='HTTP Negotiate (SPNEGO) proxy authentication support for applications.',
    long_description=open('README.md', 'r').read(),
    py_modules=['proxy_negotiate'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'gssapi',
    ],
    scripts=[
        'bin/nc-negotiate',
        'bin/proxy-negotiate',
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
