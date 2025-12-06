FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create temporary directory with proper permissions
RUN mkdir -p /app/tmp && chown -R appuser:appuser /app

# Set environment variable for temp directory
ENV TMPDIR=/app/tmp

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "run:app"]
