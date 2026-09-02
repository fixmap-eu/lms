<?php

/**
 * WeKrwiITLDAPAuthPass — LDAP password verification handler
 *
 * Hook: password_verification (upstream standard since 2026-06)
 * Fired from lib/Auth.class.php::VerifyUser() before the DB password check.
 * Sets hook_data['result'] = true on successful LDAP bind; falls back to
 * standard LMS VerifyPassword() when LDAP is not configured or bind fails.
 *
 * Security notes:
 *   - Throttle liczony po REMOTE_ADDR, nie po X-Forwarded-For (świadomie — patrz
 *     WeKrwiITLDAPAuthPassUP.php dla pełnego uzasadnienia: XFF jest kontrolowany
 *     przez klienta, zaufanie do niego otwiera trywialny bypass throttla).
 *     Po udanym bindzie resetuje się WYŁĄCZNIE licznik per-(IP+login), NIGDY
 *     licznik per-IP — ten drugi musi przetrwać sukces, bo chroni przed
 *     password-spray (jedno własne konto AD wystarczyłoby do resetowania go
 *     po każdej serii prób, czyniąc próg nieegzekwowalnym).
 *   - require_group is mandatory in practice: a bare LDAP bind only proves the
 *     caller owns SOME AD account whose name matches an LMS operator login,
 *     not that the account is meant to hold operator privileges. Leaving
 *     require_group unset makes this handler inert (falls through to local
 *     password auth) rather than trusting name equality — see onPasswordVerification().
 */
class LDAPAuthPassHandler
{
    /**
     * Persist auth type for the current request (global) AND for subsequent
     * requests (cookie). We avoid LMS Session because restore_user_settings()
     * in Auth.class.php overwrites _content with stale values from users.settings
     * after our $SESSION->save() call.
     */
    private static function persistAuthType(string $type): void
    {
        $GLOBALS['wkldap_auth_type'] = $type;

        if (!headers_sent()) {
            $secure = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on')
                || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
            setcookie('wkldap_auth', $type, [
                'expires'  => 0,
                'path'     => '/',
                'secure'   => $secure,
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
        }
    }

    public function onPasswordVerification($hook_data)
    {
        global $SESSION;

        $login  = $hook_data['login']  ?? null;
        $passwd = $hook_data['passwd'] ?? null;

        if (empty($login) || empty($passwd)) {
            return $hook_data;
        }

        $login_safe = str_replace(["\r", "\n"], '', $login); // log-injection guard

        $host     = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.host', '');
        $port     = (int) ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.port', 636);
        $suffix   = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.bind_dn_suffix', '');
        // Default fail-closed (demand): this connection carries AD/LDAP bind
        // credentials in plaintext protocol; 'allow' accepted an unverified or
        // absent cert, letting a MITM harvest passwords. Admin can still opt
        // back into 'allow' explicitly via config if their environment needs it.
        $tls_cert = strtolower(ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.tls_require_cert', 'demand'));

        if (empty($host)) {
            return $hook_data;
        }

        if (!function_exists('ldap_connect')) {
            writesyslog('WeKrwiITLDAPAuthPass: PHP ldap extension not available', LOG_ERR);
            return $hook_data;
        }

        $tls_map = [
            'never'  => LDAP_OPT_X_TLS_NEVER,
            'allow'  => LDAP_OPT_X_TLS_ALLOW,
            'demand' => LDAP_OPT_X_TLS_DEMAND,
        ];
        ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, $tls_map[$tls_cert] ?? LDAP_OPT_X_TLS_DEMAND);

        // Per-IP+login throttle (APCu, best-effort — fails open, AD's own lockout
        // is the backstop). Independent of any downstream reCAPTCHA on other paths.
        // Two-slot sliding window (150s slots, 300s self-expiring TTL each):
        // counting via apcu_add+apcu_inc stays atomic under concurrent requests
        // (unlike a fetch-then-store read-modify-write, which loses increments
        // when requests race), while summing current+previous slot still gives
        // an effective ~150-300s sliding window instead of a fixed one.
        // Normalize to bare account name (strip UPN suffix) so "user" and
        // "user@domain" share one bucket; hashed + length-bounded so the
        // attacker-controlled login text can't grow the APCu keyspace.
        $login_norm = strtolower(
            strpos($login_safe, '@') !== false ? strstr($login_safe, '@', true) : $login_safe
        );
        $slot                = intdiv(time(), 150);
        $throttle_base       = 'wkldap_staff:' . ($_SERVER['REMOTE_ADDR'] ?? '') . ':' . sha1($login_norm);
        $throttle_ip_base    = 'wkldap_staff_ip:' . ($_SERVER['REMOTE_ADDR'] ?? '');
        $throttle_key        = $throttle_base . ':' . $slot;
        $throttle_key_prev   = $throttle_base . ':' . ($slot - 1);
        $throttle_ip_key     = $throttle_ip_base . ':' . $slot;
        $throttle_ip_key_prev = $throttle_ip_base . ':' . ($slot - 1);
        if (function_exists('apcu_fetch')) {
            $fails    = (int) apcu_fetch($throttle_key) + (int) apcu_fetch($throttle_key_prev);
            $ip_fails = (int) apcu_fetch($throttle_ip_key) + (int) apcu_fetch($throttle_ip_key_prev);
            if ($fails >= 5 || $ip_fails >= 30) {
                writesyslog(
                    'WeKrwiITLDAPAuthPass: throttled (too many failed binds) for '
                        . substr($login_safe, 0, 3) . '*** from ' . ($_SERVER['REMOTE_ADDR'] ?? ''),
                    LOG_WARNING
                );
                return $hook_data;
            }
        } else {
            // Fails open by design (AD's own lockout is the backstop, see class
            // docblock) — but that used to be silent. Without APCu this bind
            // attempt is completely unthrottled; say so once per request instead
            // of leaving the missing protection undetectable in the logs.
            writesyslog('WeKrwiITLDAPAuthPass: APCu unavailable — bind throttle disabled', LOG_WARNING);
        }

        $conn = @ldap_connect(rtrim($host, '/') . ':' . $port);
        if (!$conn) {
            writesyslog('WeKrwiITLDAPAuthPass: cannot connect to ' . $host . ':' . $port, LOG_WARNING);
            return $hook_data;
        }

        ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($conn, LDAP_OPT_NETWORK_TIMEOUT, 3);

        $sam     = (strpos($login, '@') !== false) ? strstr($login, '@', true) : $login;
        $bind_dn = (strpos($login, '@') !== false) ? $login : ($login . $suffix);
        $bound   = @ldap_bind($conn, $bind_dn, $passwd);

        if ($bound) {
            // require_group is OPTIONAL, by product decision (2026-09-02): a bare
            // successful bind only proves the caller owns SOME AD account whose
            // UPN/sAMAccountName matches this LMS operator's login, not that the
            // account is meant to hold operator privileges — the same AD tree
            // also authenticates userpanel customers (see WeKrwiITLDAPAuthPassUP.php).
            // Operators deploying this plugin accept that a matching AD login is
            // sufficient (identical to pre-1.0 behavior); require_group remains
            // available for installations that want the extra membership check,
            // but its absence is no longer treated as misconfiguration.
            $base_dn        = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.base_dn', '');
            $require_group  = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.require_group', '');
            $scoped         = empty($require_group);

            if (empty($require_group)) {
                // Nothing further to check — bind success alone authorizes.
            } elseif (empty($base_dn)) {
                writesyslog('WeKrwiITLDAPAuthPass: base_dn is not configured, cannot verify require_group', LOG_ERR);
            } else {
                // Match on whatever identity the bind actually authenticated, not
                // just the bare sAMAccountName: AD resolves a UPN bind against the
                // account's explicit userPrincipalName FIRST, falling back to
                // sAMAccountName@default-domain only if no explicit UPN matches.
                // In a forest with multiple UPN suffixes / alternate UPNs, some
                // *other* account's sAMAccountName can coincide with the login's
                // UPN-prefix while that other account's own explicit UPN differs —
                // checking group membership only by sAMAccountName then risks
                // authorizing an identity that never bound. Requiring the match to
                // also carry the exact bind_dn as its userPrincipalName (or, for a
                // bare login with no bind_dn_suffix, its sAMAccountName) and
                // demanding exactly one hit closes that gap; ambiguity fails closed.
                $filter = '(&(|(userPrincipalName=' . ldap_escape($bind_dn, '', LDAP_ESCAPE_FILTER) . ')'
                    . '(sAMAccountName=' . ldap_escape($sam, '', LDAP_ESCAPE_FILTER) . '))'
                    . '(memberOf:1.2.840.113556.1.4.1941:=' . ldap_escape($require_group, '', LDAP_ESCAPE_FILTER) . '))';
                $search = @ldap_search($conn, $base_dn, $filter, ['dn', 'userprincipalname', 'samaccountname'], 0, 2, 3);
                if ($search) {
                    $entries = @ldap_get_entries($conn, $search);
                    $scoped  = $entries && $entries['count'] === 1
                        && strcasecmp($entries[0]['userprincipalname'][0] ?? '', $bind_dn) === 0;
                }
                if (!$scoped) {
                    writesyslog(
                        'WeKrwiITLDAPAuthPass: LDAP bind OK for ' . $login_safe
                            . ' but account is not a member of require_group — refusing',
                        LOG_WARNING
                    );
                }
            }

            @ldap_close($conn);

            if ($scoped) {
                writesyslog('WeKrwiITLDAPAuthPass: LDAP auth success for ' . $login_safe, LOG_INFO);
                // Reset only the per-(IP+login) key. The IP-wide key MUST survive a
                // success: it exists specifically to catch password-spray, where an
                // attacker owning one valid low-priv AD account could otherwise bind
                // with it after every ~29 guesses to wipe the shared counter and
                // spray indefinitely — resetting it would make the threshold
                // unenforceable against exactly the attacker it targets.
                if (function_exists('apcu_delete')) {
                    apcu_delete($throttle_key);
                    apcu_delete($throttle_key_prev);
                }
                self::persistAuthType('ldap');
                $hook_data['result'] = true;
                return $hook_data;
            }

            self::persistAuthType('local');
            return $hook_data;
        }

        @ldap_close($conn);

        // Masked prefix only — $login is user-typed and can contain a mistyped
        // password; never write the full raw value to syslog. No usleep() here:
        // it blocks the PHP-FPM worker itself, which an attacker can use to
        // exhaust the pool cheaper than they're slowed down (amplification).
        // Rate-limiting belongs at the WAF/AD layer, not this hook.
        writesyslog(
            'WeKrwiITLDAPAuthPass: LDAP bind failed for ' . substr($login_safe, 0, 3) . '***',
            LOG_INFO
        );
        if (function_exists('apcu_add')) {
            // $ttl on apcu_inc matters: if the key vanished between add and
            // inc (evicted, or deleted by a concurrent success-reset), inc
            // alone would recreate it with ttl=0 (permanent) — for the per-IP
            // key, which is never reset on success, that would lock the IP
            // out until PHP-FPM restart.
            apcu_add($throttle_key, 0, 300);
            apcu_inc($throttle_key, 1, $inc_ok, 300);
            apcu_add($throttle_ip_key, 0, 300);
            apcu_inc($throttle_ip_key, 1, $ip_inc_ok, 300);
        }
        self::persistAuthType('local');

        return $hook_data;
    }
}
