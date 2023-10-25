//  pam_ldapbind module, v1.0.0, 2023-10-25
//
//  Copyright (C) 2023, Martin Young <martin_young@live.cn>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or any
//  later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, see <https://www.gnu.org/licenses/>.
//------------------------------------------------------------------------

#include <stdlib.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <ldap.h>

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    const char *puser, *ppwd;
    LDAP *ldaph;

    if( argc < 1 ) {
        pam_syslog(pamh, LOG_ERR, "No option");
        return PAM_SERVICE_ERR;
    }

    if( (retval=pam_get_item(pamh, PAM_USER, (const void **)&puser)) != PAM_SUCCESS ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    if( !(puser && *puser) ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine username");
        return PAM_SERVICE_ERR;
    }

    if( (retval=pam_get_authtok(pamh, PAM_AUTHTOK, &ppwd, NULL)) != PAM_SUCCESS ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine password: %s", pam_strerror(pamh, retval));
        return retval;
    }
    if( !(ppwd && *ppwd) ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine password");
        return PAM_SERVICE_ERR;
    }

    if( (retval=ldap_initialize(&ldaph, argv[0])) != LDAP_SUCCESS ) {
        pam_syslog(pamh, LOG_ERR, "OpenLDAP library initialization failure: %s", ldap_err2string(retval));
        return PAM_SERVICE_ERR;
    }

    if( (retval=ldap_simple_bind_s(ldaph, puser, ppwd)) != LDAP_SUCCESS ) {
        pam_syslog(pamh, LOG_NOTICE, "Access denied: %s", ldap_err2string(retval));
        return PAM_AUTH_ERR;
    }

    ldap_unbind_s(ldaph);

    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

int pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}
