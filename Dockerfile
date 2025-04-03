# Use a slim Python base image
FROM python:3.11-slim

# Set environment variables to avoid buffering logs and force UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory inside container
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source code into container
COPY . .

# Make sure the data directory exists in the container (for mounted volume)
RUN mkdir -p data/keys data/shared data/downloads

# Expose default peer communication port
EXPOSE 9000

# Default container startup command
CMD ["python", "main.py"]