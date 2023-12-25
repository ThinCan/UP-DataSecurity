FROM ubuntu:latest
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "nginx", "-y"]
COPY key.key /etc/
COPY cert.crt /etc/
COPY nginx.conf1 /etc/nginx/
COPY global.pass /etc/
CMD ["nginx", "-c", "/etc/nginx/nginx.conf1"]