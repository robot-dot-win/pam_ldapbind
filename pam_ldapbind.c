//  pam_ldapbind module, v1.0.0
//
//  by Martin Young <martin_young@live.cn>, 2023-10-25

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
