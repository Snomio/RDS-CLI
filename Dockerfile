FROM python:3.6-alpine
COPY cli.py /sbin/cli.py
CMD ["python", "/sbin/cli.py"]
