#!/usr/bin/env python
from distutils.core import setup
import os

from setuptools import find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()

version = '0.0.1'

install_requires = [
    "cherrypy",
    "pyjwkest"
]

setup(name='openid-mdq',
      version=version,
      description="OpenID Connect MDQ Server",
      long_description=README,
      author='Rebecka Gulliksson',
      author_email='rebecka.gulliksson@umu.se',
      url='https://github.com/its-dirg/openid-mdq',
      tests_require=["pytest", "mock", "requests"],
      packages=find_packages('src'),
      package_dir={'': 'src'},
      zip_safe=False,
      install_requires=install_requires,
      entry_points={
          'console_scripts': ['openid-mdq=mdq.server:main']
      }
)