FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

# Initialize DB on build (optional, will be recreated on start)
RUN python -c "from collector import init_db; init_db()"

# Run with gunicorn
CMD gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 wsgi:app
