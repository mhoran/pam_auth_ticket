# pam_auth_ticket

This PAM module allows reuse of previously successful authentication credentials on subsequent authentication requests (think sudo).

This feature is particularly useful for those who may be utilizing one-time passwords (OTP) for authentication, where the OTP may only be used once. Non-OTP aware applications may present the OTP multiple times for authentication requests, which would normally be considered invalid.

This module checks the incoming password against a previously successful password, and verifies that no more than 60 (to be configurable) seconds have passed since the last successful authentication request. When the module is configured as `sufficient` for authentication requests, it will bypass the normal authentication flow.

## Usage

To enable `pam_auth_ticket` to cache credentials for the `dovecot` service, add the following to your `pam.d` directory:

```
auth	sufficient	/home/mhoran/pam_auth_ticket/pam_auth_ticket.so debug
auth	requisite	/usr/local/lib/security/pam_oath.so usersfile=/usr/local/etc/users.oath digits=6
auth	required	pam_unix.so use_first_pass
account	required	pam_unix.so
session	required	/home/mhoran/pam_auth_ticket/pam_auth_ticket.so debug
```
