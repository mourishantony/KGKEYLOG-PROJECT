FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements first (for Docker layer caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Make entrypoint script executable
RUN chmod +x entrypoint.sh

# Expose port (Render uses PORT env variable)
EXPOSE 5000

# Run seed_db.py then start gunicorn via entrypoint script
CMD ["./entrypoint.sh"]
