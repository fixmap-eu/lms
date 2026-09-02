<?php

/**
 * WeKrwiITLDAPAuthPass — toolbar badge handler
 *
 * Hook: smarty_initialized
 * Injects a small auth-type badge (AD / LMS) before the logout link
 * using a Smarty output filter — works on any theme, no template changes needed.
 */
class LDAPAuthSmartyHandler
{
    public function onSmartyInitialized($SMARTY)
    {
        // pluginlist.html uses LMSPluginManager::LAST_PRIORITY — register so Smarty doesn't warn
        if (class_exists('LMSPluginManager')) {
            $SMARTY->registerClass('LMSPluginManager', 'LMSPluginManager');
        }

        // Same request: set by LDAPAuthPassHandler::persistAuthType() via $GLOBALS
        // Subsequent requests: read from cookie set on login
        $auth_type = $GLOBALS['wkldap_auth_type'] ?? ($_COOKIE['wkldap_auth'] ?? null);

        if (empty($auth_type)) {
            return $SMARTY;
        }

        $SMARTY->registerFilter('output', function ($output) use ($auth_type) {
            // Skip AJAX / non-HTML responses
            if (stripos($output, '</body>') === false) {
                return $output;
            }

            if ($auth_type === 'ldap') {
                $badge = '<span'
                    . ' title="Uwierzytelniony przez LDAP/Active Directory"'
                    . ' style="display:inline-block;padding:1px 6px;margin:0 4px 0 0;'
                    . 'font:bold 10px/16px monospace;border-radius:3px;vertical-align:middle;'
                    . 'background:#1565C0;color:#fff;letter-spacing:.5px;">AD</span>';
            } else {
                $badge = '<span'
                    . ' title="Uwierzytelniony lokalnie (hasło LMS)"'
                    . ' style="display:inline-block;padding:1px 6px;margin:0 4px 0 0;'
                    . 'font:bold 10px/16px monospace;border-radius:3px;vertical-align:middle;'
                    . 'background:#546E7A;color:#fff;letter-spacing:.5px;">LMS</span>';
            }

            // Insert badge immediately before the logout anchor
            if (preg_match('/(<a\b[^>]*\bid=["\']logout["\'][^>]*>)/is', $output, $m, PREG_OFFSET_CAPTURE)) {
                $output = substr_replace($output, $badge, $m[0][1], 0);
            }

            return $output;
        });

        return $SMARTY;
    }
}
