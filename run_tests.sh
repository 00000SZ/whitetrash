#!/bin/bash

TESTENV=test-env

# Test environment setup with virtualenv and pip
if [ -f $TESTENV/bin/activate ]
then
    echo Test environment already exists
else
    echo Creating test environment
    virtualenv --distribute --no-site-packages $TESTENV -q
    echo Installing packages to test environment
    pip install -E $TESTENV -r testing/pip-testing-req.txt -q
    source $TESTENV/bin/activate
fi

# All necessary environment variables whitetrash go here
export PYTHONPATH=`pwd`
export DJANGO_SETTINGS_MODULE=django_site.whitetrash.settings

# All testing stuff goes here
echo Beginnning tests...
echo

python -c "import redirector.whitetrash2"; exit $?
