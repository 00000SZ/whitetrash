#!/bin/bash

TESTENV=.virtualenv

# Test environment setup with virtualenv and pip
if [ -f $TESTENV/bin/activate ]
then
    echo Test environment already exists
else
    echo Creating test environment
    virtualenv --distribute --no-site-packages $TESTENV -q
fi

# Install packages only if necessary
pip -E $TESTENV freeze > pip-installed.tmp
diff pip-installed.tmp tests/pip-testing-req.txt > /dev/null
if [ $? -eq 0 ]
then
    echo Test environment already up to date
else
    echo Installing packages to test environment
    pip install -E $TESTENV -r tests/pip-testing-req.txt -q
fi
rm pip-installed.tmp

# All necessary environment variables whitetrash go here
export PYTHONPATH=`pwd`
export DJANGO_SETTINGS_MODULE=django_site.whitetrash.settings

# All testing stuff goes here
echo Beginnning tests...
echo
source $TESTENV/bin/activate
python -c "import redirector.whitetrash_redir"; exit $?
