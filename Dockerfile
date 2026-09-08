FROM python:3.14-alpine

RUN apk add --no-cache whois

WORKDIR /app
COPY watcher.py .

VOLUME ["/data"]

CMD ["python", "-u", "watcher.py"]
