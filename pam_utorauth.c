
/* Include PAM headers */

#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* OpenPAM has a few extra bits */
#include <security/openpam.h>

/* Kerberos headers */

#include <krb5.h>
#include <com_err.h>

/* Necessary to get (e.g.) krb5_error_code defined as a symbol */
#define	COMPAT_MIT

#define krb5_get_err_text(c,e) error_message(e)

/* Define which PAM interfaces we provide */

#define PAM_SM_AUTH

/* Utility macro to make for easy logging */

#define	PAM_LOG(...) \
	openpam_log(PAM_LOG_DEBUG, __VA_ARGS__)

#define	PAM_VERBOSE_ERROR(...) \
	openpam_log(PAM_LOG_ERROR, __VA_ARGS__)

/* Additional headers for fun */

#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define USER_PROMPT		"Username: "
#define PASSWORD_PROMPT		"Password:"
#define OPTION_DOMAIN "domain"

/* PAM entry point for authentication verification */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	PAM_LOG( "START UTORAUTH pam_sm_authenticate()" );

	krb5_error_code krbret;
	krb5_context pam_context;
	krb5_creds creds;
	krb5_principal princ;
	krb5_get_init_creds_opt *opts = NULL;
	int retval = 0;
	const char *user;
	char *pass;
	const void *sourceuser, *service;
	char *principal = NULL, *princ_name = NULL;
	char *default_domain = NULL;

	PAM_LOG( "Checking parameters" );
	default_domain = (char *) openpam_get_option(pamh, OPTION_DOMAIN);
	PAM_LOG("%s=[%s]", OPTION_DOMAIN, default_domain );

	retval = pam_get_user(pamh, &user, USER_PROMPT);

	if (retval != PAM_SUCCESS)
	{
		PAM_LOG("Problem with pam_get_user() [%d]", retval);
		return (retval);
	}
	
	PAM_LOG("Got user: %s", user);

	retval = pam_get_item(pamh, PAM_RUSER, &sourceuser);

	if (retval != PAM_SUCCESS)
	{
		PAM_LOG("Problem with pam_get_item(PAM_RUSER) [%d]", retval);
		return (retval);
	}
	
	PAM_LOG("Got ruser: %s", (const char *)sourceuser);

	service = NULL;
	pam_get_item(pamh, PAM_SERVICE, &service);

	if (service == NULL)
	{
		service = "unknown";
	}

	PAM_LOG("Got service: %s", (const char *)service);

	if (strchr(user, '@')) 
	{
		principal = strdup(user);
	}
	else
	{
		principal = malloc(strlen(user) + strlen(default_domain) + 1);

	    if (principal) // thanks @pmg
	    {
	        strcpy(principal, user);
	        strcat(principal, default_domain);
	    }

	};

	PAM_LOG("Using principal: %s", (const char *)principal);
	
	krbret = krb5_init_context(&pam_context);
	
	if (krbret != 0)
	{
		PAM_VERBOSE_ERROR("Problem with krb5_init_context() [%d]", krbret);
		return (PAM_SERVICE_ERR);
	};

	PAM_LOG("Initialized Kerberos Context");

	if (principal == NULL)
	{
		PAM_LOG("Failed to determine Kerberos principal name.");
		retval = PAM_SERVICE_ERR;
		goto cleanup3;
	};

	krbret = krb5_get_init_creds_opt_alloc(pam_context, &opts);
	
	if (krbret) 
	{
		PAM_VERBOSE_ERROR("Problem with krb5_get_init_creds_opt_alloc() [%d]", krbret);
		retval = PAM_SERVICE_ERR;
		goto cleanup3;
	};

	krbret = krb5_parse_name(pam_context, principal, &princ);
	free(principal);
	if (krbret != 0) {
		PAM_LOG("Error krb5_parse_name(): %s",
		    krb5_get_err_text(pam_context, krbret));
		PAM_VERBOSE_ERROR("Kerberos 5 error");
		retval = PAM_SERVICE_ERR;
		goto cleanup3;
	}

	PAM_LOG("Done krb5_parse_name()");

	/* Now convert the principal name into something human readable */
	princ_name = NULL;
	krbret = krb5_unparse_name(pam_context, princ, &princ_name);
	if (krbret != 0) 
	{
		PAM_LOG("Error krb5_unparse_name(): %s", krb5_get_err_text(pam_context, krbret));
		PAM_VERBOSE_ERROR("Kerberos 5 error");
		retval = PAM_SERVICE_ERR;
		goto cleanup2;
	}

	PAM_LOG("Got principal: %s", princ_name);

	/* Get password */
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&pass, PASSWORD_PROMPT);
	if (retval != PAM_SUCCESS)
	{
		goto cleanup2;
	}

	PAM_LOG("Got password");

	PAM_LOG("Attempting to get non-forwardable TGT.");

	memset(&creds, 0, sizeof(krb5_creds));
	krbret = krb5_get_init_creds_password(pam_context, &creds, princ,
		pass, NULL, pamh, 0, NULL, opts);

	if (krbret != 0)
	{
		PAM_VERBOSE_ERROR("Kerberos 5 error");
		PAM_LOG("Error krb5_get_init_creds_password(): %s", krb5_get_err_text(pam_context, krbret));
		retval = PAM_AUTH_ERR;
		goto cleanup2;
	}

	PAM_LOG("Got TGT");

	krb5_free_cred_contents(pam_context, &creds);
	PAM_LOG("Done basic cleanup");
cleanup2:
	krb5_free_principal(pam_context, princ);
	PAM_LOG("Done cleanup2");
cleanup3:
	if (princ_name)
	{
		free(princ_name);
	}

	if (opts)
	{
		krb5_get_init_creds_opt_free(pam_context, opts);
	}

	krb5_free_context(pam_context);

	PAM_LOG("Done cleanup3");

	if (retval != PAM_SUCCESS)
	{
		PAM_LOG("Kerberos 5 refuses you");
	}

	PAM_LOG( "END UTORAUTH pam_sm_authenticate() returning[%d]", retval );
	
	return (retval);
}
