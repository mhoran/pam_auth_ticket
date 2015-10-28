all:
	cc -Wall -fPIC -DPIC -pedantic pam_auth_ticket.c -o pam_auth_ticket.so -shared -s -lpam -lm -lssl
