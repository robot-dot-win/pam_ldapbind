## DESCRIPTION
pam_ldapbind is a Linux PAM module which provides a way to authenticate users against an LDAP server via binding login.

On success it returns PAM_SUCCESS, otherwise it returns PAM_AUTH_ERR, PAM_SERVICE_ERR, PAM_BUF_ERR or PAM_PERM_DENIED.

No credentials are awarded by this module.
## BUILD
The source program is a single C99 file.

Requires: pam-devel, openldap-devel

```bash
$ gcc pam_ldapbind.c -o pam_ldapbind.so -shared -fPIC -lpam -lldap -std=c99 -Wno-implicit-function-declaration
```
## USAGE
```
pam_ldapbind.so <ldap_uri>
```
Example:
```
auth    required    pam_ldapbind.so     ldaps://ldap.company1.com
```
or
```
auth    required    pam_ldapbind.so     ldaps://ldap.company2.com:637
```
## LICENSE
pam_ldapbind is licensed under the [GPLv3](LICENSE) license.
