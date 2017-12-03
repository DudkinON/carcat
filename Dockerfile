FROM ubuntu:16.04
MAINTAINER Oleg Dudkin "mail@oleg-dudkin.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential
COPY ./requirements.txt /items_catalog/requirements.txt
WORKDIR /items_catalog
RUN pip install -r requirements.txt
COPY . /items_catalog
ENTRYPOINT ["python"]
CMD ["main.py"]