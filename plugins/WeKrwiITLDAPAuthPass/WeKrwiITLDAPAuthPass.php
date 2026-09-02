<?php

/**
 * WeKrwiITLDAPAuthPass — LMS Plugin (new-style, metadata + admin hooks)
 *
 * Actual userpanel authentication is handled by the companion old-style plugin:
 *   lib/plugins/WeKrwiITLDAPAuthPass.php
 *
 * That file fires inline before Session is constructed in userpanel/index.php,
 * performs LDAP bind against Synology/AD, creates the up_sessions row directly
 * and redirects — all without touching Session.class.php or any core file.
 *
 * This new-style class exists so the plugin appears in the LMS admin plugin
 * list and its locales are loaded.
 *
 * Activation (lms.ini):
 *   [phpui]
 *   plugins = ... WeKrwiITLDAPAuthPass
 *
 * Configuration (lms.ini):
 *   [WeKrwiITLDAPAuthPass]
 *   host             = ldaps://ldap.example.org
 *   port             = 636
 *   base_dn          = DC=ad,DC=example,DC=org
 *   bind_dn_suffix   = @ad.example.org
 *   ldap_mail_attr   = mail
 *   tls_require_cert = demand       ; never | allow | demand (default: demand, fail-closed)
 *   ; allowed_status =              ; comma-sep ints; empty = all statuses
 *   ; require_group   =             ; AD security group DN (recursive). REQUIRED for
 *                                   ; operator (admin-panel) LDAP sign-in — without it
 *                                   ; the password_verification handler never shortcuts
 *                                   ; auth, since name equality alone does not prove an
 *                                   ; AD account should hold LMS operator privileges.
 *
 * (C) 2026 Przemysław 'djrzulf' Knycz / WeKrwi.IT
 */

class WeKrwiITLDAPAuthPass extends LMSPlugin
{
    const PLUGIN_NAME        = 'WeKrwi.IT-LDAPAuthPass';
    const PLUGIN_DESCRIPTION = 'LDAP/AD pass-through authentication for LMS operators and userpanel customers';
    const PLUGIN_AUTHOR      = "Przemysław 'djrzulf' Knycz &lt;przemyslaw@wekrwi.it&gt;";
    const PLUGIN_SOFTWARE_VERSION = '1.0.0';

    public function registerHandlers()
    {
        $this->handlers = [
            // Admin LMS: called from Auth.class.php::VerifyUser() before DB password check
            'password_verification' => [
                'class'  => 'LDAPAuthPassHandler',
                'method' => 'onPasswordVerification',
            ],
            // Toolbar badge: inject AD/LMS indicator before logout link (theme-independent)
            'smarty_initialized' => [
                'class'  => 'LDAPAuthSmartyHandler',
                'method' => 'onSmartyInitialized',
            ],
        ];
    }
}
