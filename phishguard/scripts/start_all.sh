#!/bin/bash

source /home/ubuntu/phishguard/venv/bin/activate

# Run flask_app.py which includes both dashboard and ingestion logic
exec gunicorn --bind 127.0.0.1:8000 flask_app:app

