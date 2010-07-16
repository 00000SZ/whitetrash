#!/bin/bash

virtualenv --distribute --no-site-packages test-env
pip install -E test-env -r testing/pip-testing-req.txt
source test-env/bin/activate

python -c "import django"

deactivate
