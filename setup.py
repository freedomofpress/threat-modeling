import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="threat_modeling",
    version="0.0.1",
    author="redshiftzero",
    author_email="jen@redshiftzero.com",
    description="Threat modeling tools",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/redshiftzero/threat-modeling",
    packages=['threat_modeling', 'threat_modeling.enumeration'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 3 - Alpha",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Visualization",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    scripts=['bin/threatmodel'],
    install_requires=["pygraphviz>=1.5", "PyYAML>=5.3"],
)
