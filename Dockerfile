FROM python:3.12-alpine

RUN apk add --no-cache whois

WORKDIR /app
COPY checker.py .

VOLUME ["/data"]

CMD ["python", "-u", "checker.py"]
