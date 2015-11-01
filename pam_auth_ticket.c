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
#include <stdbool.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#define TIMEOUT 600
#define AUTH_TICKET_PATH "/tmp/auth_tickets"

void write_ticket(const char *user, const char* data);
static bool read_ticket(const char *user, int *timestamp, char **password);
static void cleanup(pam_handle_t *pamh, void *data, int error_status);
static char* gen_salt();

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	const char *user;
	char *password, *crypt_password, *cached_password;
	int pam_err, timestamp;

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if (getpwnam(user) == NULL)
		return (PAM_USER_UNKNOWN);

	/* get password */
	pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
	    (const char **)&password, NULL);
	if (pam_err == PAM_CONV_ERR)
		return (pam_err);
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);

	cached_password = NULL;
	if (!read_ticket(user, &timestamp, &cached_password)) {
		pam_err = PAM_AUTH_ERR;
		if (crypt_set_format("sha512"))
			crypt_password = crypt(password, gen_salt());
		else
			crypt_password = NULL;
		goto done;
	}

	if ((crypt_password = crypt(password, cached_password)) != NULL &&
	    strcmp(crypt_password, cached_password) == 0) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		/* TODO: timeout should be an argument! */
		if ((int)now.tv_sec > timestamp + TIMEOUT) {
			openpam_log(PAM_LOG_DEBUG,
				"expired auth ticket: %d > %d",
				(int)now.tv_sec, timestamp + TIMEOUT);
			pam_err = PAM_AUTH_ERR;
		} else {
			pam_err = PAM_SUCCESS;
		}
	} else {
		openpam_log(PAM_LOG_DEBUG, "passwords do not match");
		pam_err = PAM_AUTH_ERR;
	}
done:
	if (crypt_password != NULL) {
		char *cp;
		size_t len;
		len = strlen(crypt_password) + 1;
		if ((cp = calloc(len, sizeof(char))) != NULL &&
		    strlcpy(cp, crypt_password, len) < len)
			pam_set_data(pamh, "pam_auth_ticket", cp, cleanup);
	}

	free(cached_password);
	return (pam_err);
}

static void
cleanup(pam_handle_t *pamh, void *data, int error_status) {
	free(data);
}

static char*
gen_salt() {
	static char salt[16+1];
	const char *const seedchars =
	    "./0123456789ABCDEFGHIJKLMNOPQRST"
	    "UVWXYZabcdefghijklmnopqrstuvwxyz";
	for (int i = 0; i < 16; i++)
		salt[i] = seedchars[arc4random_uniform(strlen(seedchars))];
	salt[sizeof(salt) - 1] = '\0';
	return salt;
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
	const char *user;
	const void *data;

	if (pam_get_user(pamh, &user, NULL) == PAM_SUCCESS &&
	    pam_get_data(pamh, "pam_auth_ticket", &data) == PAM_SUCCESS)
		write_ticket(user, (const char*)data);

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

static bool
read_ticket(const char *user, int *timestamp, char **password)
{
	int fd, word_count;
	FILE *f;
	char **words;
	bool success = false;
	
	if ((fd = open(AUTH_TICKET_PATH, O_RDONLY|O_SHLOCK)) < 0 ||
	    (f = fdopen(fd, "r")) == NULL) {
		if (fd >= 0)
			close(fd);
		return (false);
	}

	words = openpam_readlinev(f, NULL, &word_count);
	while (words != NULL) {
		if (word_count != 3 || strcmp(user, words[0]) != 0) {
			for(int i = 0; i < word_count; i++) {
				free(words[i]);
			}
			free(words);
			words = openpam_readlinev(f, NULL, &word_count);
			continue;
		}

		*password = words[1];
		const char *err;
		*timestamp = strtonum(words[2], 0, INT_MAX - TIMEOUT, &err);
		success = (err == NULL);

		free(words[0]);
		free(words[2]);
		free(words);
		words = NULL;
	}
	fclose(f);
	return (success);
}

void
write_ticket(const char* user, const char* data)
{
	int fd, flags;
	FILE *f;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	flags = O_WRONLY|O_CREAT|O_TRUNC|O_EXLOCK;
	if ((fd = open(AUTH_TICKET_PATH, flags, 0600)) >= 0 &&
	    (f = fdopen(fd, "w")) != NULL) {
		fprintf(f, "%s %s %d\n", user, data, (int)now.tv_sec);
		fclose(f);
	} else if (fd >= 0)
		close(fd);

}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_auth_ticket")
#endif
