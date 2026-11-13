FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Set Python path so argus package is importable
ENV PYTHONPATH=/app/src

# Expose API port
EXPOSE 8001

# Run FastAPI with uvicorn
CMD ["uvicorn", "argus.api.main:app", "--host", "0.0.0.0", "--port", "8001"]
