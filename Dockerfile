# Use a slim Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project code
COPY . .

# Open port for incoming peer connections (e.g., 9000)
EXPOSE 9000

# Default command
CMD ["python", "main.py"]