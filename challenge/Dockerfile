FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nginx \
    supervisor \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install --with-deps chromium

COPY . .

COPY nginx.conf /etc/nginx/sites-available/default

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN mkdir -p /var/cache/nginx && chown -R www-data:www-data /var/cache/nginx

ENV APP_URL=http://localhost

EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
