# Dockerfile
FROM python:3.9.7-buster

RUN mkdir /code
ADD . /code/
WORKDIR /code

RUN pip install --upgrade pip
RUN apt add gcc musl-dev python3-dev libffi-dev openssl-dev cargo jpeg-dev zlib-dev
RUN apt update && apt add postgresql-dev gcc python3-dev musl-dev
RUN pip install wheel

RUN git clone \
    --recursive \
    --branch patch-1 \
    https://github.com/dmontagu/uvloop.git
WORKDIR /uvloop/
RUN pip3 install -r ./requirements.dev.txt
RUN make -j2
RUN pip3 install ./
RUN rm -rf /uvloop/

RUN pip install psycopg2
RUN pip install -r requirements.txt
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "tancho.main:app", "--bind", "127.0.0.1:8004"]