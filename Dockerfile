FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt requirements-enterprise.txt* ./
RUN pip install --no-cache-dir -r requirements.txt
RUN if [ -f requirements-enterprise.txt ]; then pip install --no-cache-dir -r requirements-enterprise.txt; fi

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

EXPOSE 8000

CMD ["uvicorn", "enterprise.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
