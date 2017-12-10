FROM ubuntu:16.04
MAINTAINER Oleg Dudkin "mail@oleg-dudkin.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["main.py"]