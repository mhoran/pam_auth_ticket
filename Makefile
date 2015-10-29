all: pam_auth_ticket.so

pam_auth_ticket.so: pam_auth_ticket.c
	cc -Wall -fPIC -pedantic pam_auth_ticket.c -o pam_auth_ticket.so -shared -s -lpam -lm -lssl

install: all
	install pam_auth_ticket.so /usr/local/lib/security
