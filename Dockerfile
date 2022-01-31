# syntax=docker/dockerfile:1
FROM python:3.9-slim
WORKDIR /app
ENV STAGE PROD
RUN apt-get update
RUN apt-get install python3-dev default-libmysqlclient-dev gcc  -y
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
RUN pip install mysqlclient
COPY . .
CMD [ "python", "app.py"]