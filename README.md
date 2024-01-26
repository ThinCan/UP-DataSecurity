This was made as a university project.
The application is set up by just running  `docker-compose up`.
NGINX starts in https only mode, serves the frontend, made in alpinejs,
and acts as a reverse proxy to the backend, written in python's flask.

Application simulates banking app.
You make an account with email, password, name and lastname.
The password's strength is checked by calculating entropy bits, checking the
database of cracked passwords.

The password is stored as `(n+1)*32bits`, where `n` is the length in letters of typed password.
It is then transformed into shares, using Shamir's secret sharing scheme, and the system, when logging
in, requires 5 random letters from the password.

Name and account number are encrypted with AES in ECB mode; session and authentication is achieved with JWT.

You can also reset your password by having an email sent to you with a secret, but sending itself is not implemented.
