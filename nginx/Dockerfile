FROM nginx
COPY key.key /etc/
COPY cert.crt /etc/
COPY nginx.conf /etc/nginx/
COPY global.pass /etc/
COPY html /usr/share/nginx/html/
CMD ["/etc/init.d/nginx", "restart"]
