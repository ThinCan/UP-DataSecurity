FROM ubuntu:latest
COPY server.py /
COPY sss.py /
COPY .env /
COPY passwords.txt /
COPY requirements.txt /
RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y
RUN pip3 install -r requirements.txt
CMD python3 /server.py
EXPOSE 8080