# -*- coding: utf-8 -*-
#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name="packetracer",
      version="1.2",
      author="Arash Hatami",
      author_email="hatamiarash7@gmail.com",
      url="https://github.com/hatamiarash7/PacketTracer",
      description="Packet Tracer: The fast and simple packet creating and parsing module",
      license="MIT",
      packages=[
          "packetracer",
          "packetracer.layer12",
          "packetracer.layer3",
          "packetracer.layer4",
          "packetracer.layer567"
      ],
      package_data={"packetracer": ["oui_stripped.txt"]},
      classifiers=[
          "Development Status :: 6 - Mature",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: MIT License",
          "Natural Language :: English",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: Implementation :: CPython",
          "Programming Language :: Python :: Implementation :: PyPy"
      ],
      install_requires=[
		  "netifaces",
      ],
      python_requires=">=3.3.*"
      )
