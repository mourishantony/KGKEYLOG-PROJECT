#!/bin/bash
set -e

echo "🌱 Running database seeder..."
python seed_db.py

echo "🚀 Starting application..."
exec gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
