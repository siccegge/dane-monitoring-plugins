#!/usr/bin/python3

from setuptools import setup

setup(name='DANE monitoring plugins',
      version='0.1-alpha1',
      description='DANE aware monitoring plugins',
      author='Christoph Egger',
      author_email='christoph@christoph-egger.org',
      url='https://git.siccegge.de/?p=dane-monitoring-plugins.git',
      packages=['check_dane'
            ],
      scripts=['check_dane_smtp'
          ],
)
