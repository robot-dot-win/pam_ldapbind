//  pam_ldapbind module, v2.0.0, 2026-05-09
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

#include <memory>
#include <cstring>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <ldap.h>

using namespace std;

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *puser {nullptr};
    const char *ppwd  {nullptr};

    auto release_hd = [](LDAP *hd) { ldap_unbind_ext_s(hd,nullptr,nullptr); };

    try {
        if (argc < 1) {
            pam_syslog(pamh, LOG_ERR, "No LDAP URI option");
            return PAM_SERVICE_ERR;
        }

        if (int retval {pam_get_item(pamh, PAM_USER, (const void **)&puser)}; retval != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "Cannot get username: %s", pam_strerror(pamh, retval));
            return PAM_SERVICE_ERR;
        }
        if (!(puser && *puser)) {
            pam_syslog(pamh, LOG_NOTICE, "Empty username");
            return PAM_AUTH_ERR;
        }

        if( int retval {pam_get_authtok(pamh, PAM_AUTHTOK, &ppwd, nullptr)}; retval != PAM_SUCCESS ) {
            pam_syslog(pamh, LOG_ERR, "Cannot get password: %s", pam_strerror(pamh, retval));
            return PAM_SERVICE_ERR;
        }
        if( !(ppwd && *ppwd) ) {
            pam_syslog(pamh, LOG_NOTICE, "Empty password");
            return PAM_AUTH_ERR;
        }

        LDAP *ldaph {nullptr};
        if( int retval {ldap_initialize(&ldaph, argv[0])}; retval != LDAP_SUCCESS ) {
            pam_syslog(pamh, LOG_ERR, "LDAP init failed: %s", ldap_err2string(retval));
            return PAM_SERVICE_ERR;
        }
        unique_ptr<LDAP, decltype(release_hd)> uhd(ldaph, release_hd);

        if( int version{LDAP_VERSION3}; ldap_set_option(ldaph, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "Cannot set LDAPv3: %m");
            return PAM_SERVICE_ERR;
        }

        struct berval cred { strlen(ppwd), (char *)ppwd };
        if( int retval {ldap_sasl_bind_s(ldaph, puser, LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr)}; retval != LDAP_SUCCESS) {
            pam_syslog(pamh, LOG_NOTICE, "LDAP bind failed: %s", ldap_err2string(retval));
            return PAM_AUTH_ERR;
        }

        pam_syslog(pamh, LOG_INFO, "LDAP bind success for user %s", puser);
        return PAM_SUCCESS;
    } catch (const exception& e) {
        pam_syslog(pamh, LOG_ERR, "Standard exception caught: %s", e.what());
    } catch (...) {
        pam_syslog(pamh, LOG_ERR, "Unknown exception caught");
    }
    return PAM_SERVICE_ERR;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}
