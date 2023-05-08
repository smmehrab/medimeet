#!/usr/bin/env bash
# exit on error
set -o errexit

pip install pipenv
pipenv install
pipenv shell

python manage.py makemigrations main
python manage.py migrate main
python manage.py makemigrations
python manage.py migrate
