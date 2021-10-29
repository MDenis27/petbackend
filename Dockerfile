# Dockerfile
FROM python:3.9.6-alpine

RUN mkdir /code
ADD . /code/
WORKDIR /code

RUN pip install --upgrade pip
RUN apk add gcc musl-dev python3-dev libffi-dev openssl-dev cargo jpeg-dev zlib-dev
RUN apk update && apk add postgresql-dev gcc python3-dev musl-dev
RUN pip install psycopg2
RUN pip install -r requirements.txt
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "tancho.main:app", "--bind", "127.0.0.1:8004"]


# pull the official docker image
FROM python:3.9.4-slim

# set work directory
WORKDIR /tancho

# set env variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# copy project
COPY . .