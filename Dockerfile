FROM python:2.7-alpine

COPY requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY ./ssl-check.py /usr/local/bin/ssl-check
