/*-
 * Copyright (c) 2015 Matthew Horan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

// TODO: expire token on pass change

#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <openssl/sha.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define TIMEOUT 600

static int write_ticket();
static int read_ticket();
void cleanup(pam_handle_t *pamh, void *data, int error_status);

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	struct passwd *pwd;
	const char *user;
	char *crypt_password, *password;
	int pam_err, retry;

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if ((pwd = getpwnam(user)) == NULL)
		return (PAM_USER_UNKNOWN);

	/* get password */
	for (retry = 0; retry < 3; ++retry) {
		pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
		    (const char **)&password, NULL);
		if (pam_err == PAM_SUCCESS)
			break;
	}
	if (pam_err == PAM_CONV_ERR)
		return (pam_err);
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	/* FIXME: what happens if password is ! or *? */
	if ((!pwd->pw_passwd[0] && (flags & PAM_DISALLOW_NULL_AUTHTOK)))
		pam_err = PAM_AUTH_ERR;
	else if ((crypt_password = crypt(password, pwd->pw_passwd)) == NULL)
		pam_err = PAM_AUTH_ERR;
	else {
		char *cp;
		size_t len = strlen(crypt_password) + 1;
		if ((cp = calloc(len, sizeof(char))) == NULL ||
		    strlcpy(cp, crypt_password, len) > len)
			pam_set_data(pamh, "pam_auth_ticket", NULL, NULL);
		else
			pam_set_data(pamh, "pam_auth_ticket", cp, cleanup);

		/* TODO: timeout should be an argument! */
		int n, timestamp;
		if ((n = (int)now.tv_sec) >
		    (timestamp = read_ticket(crypt_password)) + TIMEOUT) {
			openpam_log(PAM_LOG_DEBUG,
			    "expired auth ticket: %d > %d", n,
			    timestamp + TIMEOUT);
			pam_err = PAM_AUTH_ERR;
		} else
			pam_err = PAM_SUCCESS;
	}

	return (pam_err);
}

void cleanup(pam_handle_t *pamh, void *data, int error_status) {
	free(data);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

/* needed? */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	const void *data;
	pam_get_data(pamh, "pam_auth_ticket", &data);
	if (data != NULL)
		write_ticket((const char*)data);

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

/* needed? */
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

static int
read_ticket(char* crypt_password)
{
	char *filename = "/tmp/auth_tickets";
	int timestamp = 0;
	FILE *f;
	char *cached_password, *ts;
	size_t len;
	
	if ((f = fopen(filename, "r")) == NULL)
		return (0);

	if ((cached_password = openpam_readword(f, NULL, &len)) != NULL) {
		if (strncmp(crypt_password, cached_password, len) == 0) {
			if ((ts = openpam_readword(f, NULL, NULL)) != NULL) {
				const char *errstr;
				timestamp = strtonum(ts, 0, INT_MAX - TIMEOUT,
				    &errstr);
				if (errstr != NULL)
					timestamp = 0;
				free(ts);
			} else {
				openpam_log(PAM_LOG_ERROR,
				    "failed to read timestamp");
			}
		} else {
			openpam_log(PAM_LOG_DEBUG, "passwords do not match");
		}

		free(cached_password);
	} else {
		openpam_log(PAM_LOG_ERROR, "failed to read cached password");
	}
	fclose(f);
	return (timestamp);
}

static int
write_ticket(char* data)
{
	char *keyfile = "/tmp/auth_tickets";
	int fd, len, pam_err;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	int now_digits = floor(log10(abs((int)now.tv_sec))) + 1;
	char ts[now_digits + 1];
	snprintf(ts, sizeof(ts), "%d", (int)now.tv_sec);

	len = 0;
	fd = -1;
	pam_err = PAM_SYSTEM_ERR;
	len = strlen(data);
	if ((fd = open(keyfile, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0 ||
	    write(fd, data, len) != len || write(fd, " ", 1) != 1 ||
	    write(fd, ts, strlen(ts)) != strlen(ts) ||
	    write(fd, "\n", 1) != 1) {
		openpam_log(PAM_LOG_ERROR, "%s: %m", keyfile);
		goto done;
	}
	pam_err = PAM_SUCCESS;
done:
	if (fd >= 0)
		close(fd);
	return (pam_err);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_auth_ticket")
#endif
