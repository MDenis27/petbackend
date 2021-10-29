FROM python:3.9
ENV PYTHONUNBUFFERED 1

ADD /tancho /tancho/
ADD requirements.txt /tancho/
WORKDIR /tancho

RUN pip install --upgrade pip
RUN pip install -r requirements.txt
