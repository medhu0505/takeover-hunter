FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -sL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Go tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master

ENV PATH="${PATH}:/root/go/bin"

# Copy app
COPY . .

EXPOSE 3000

# Run via Gunicorn WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:3000", "--workers", "2", "--threads", "8", "--timeout", "120", "wsgi:app"]
