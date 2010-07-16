#!/bin/bash

virtualenv --distribute --no-site-packages test-env
pip install -E test-env -r testing/pip-testing-req.txt
source test-env/bin/activate

export PYTHONPATH=`pwd`
export DJANGO_SETTINGS_MODULE=django_site.whitetrash.settings

python -c "import redirector.whitetrash2"
exit $?
