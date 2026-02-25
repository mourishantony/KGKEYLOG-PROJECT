#!/bin/bash

echo "🌱 Running database seeder..."
python seed_db.py 2>&1 || echo "⚠️ Seeder failed (non-fatal), continuing to start app..."

echo "🚀 Starting application..."
exec gunicorn app:app --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120
