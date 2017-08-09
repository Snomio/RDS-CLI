FROM python:3.5-alpine
COPY cli.py /sbin/cli.py
CMD ["python", "/sbin/cli.py"]
