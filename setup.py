#!/usr/bin/env python

from distutils.core import setup

setup(name='bbgen',
      version='0.1dev',
      description='BB-gen Simple Packet Crafter',
      long_description=open('README.md').read(),
      author='Fabricio',
      author_email='frodri@dca.fee.unicamp.br',
      url='https://github.com/ecwolf/BB-gen/',
      license='BSD-3',
      packages=['src','lib',],
     )
