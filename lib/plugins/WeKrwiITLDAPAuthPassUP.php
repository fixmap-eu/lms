<?php

/**
 * WeKrwiITLDAPAuthPass — userpanel LDAP/AD authentication (old-style plugin)
 *
 * Executes inline in userpanel/index.php BEFORE new Session() is constructed.
 * Intercepts loginform POST, attempts LDAP bind against Synology/AD, then —
 * on success — writes a session row directly to up_sessions, sets the USID
 * cookie and HTTP-redirects. The browser re-requests the same URL; this time
 * Session::_restoreSession() picks up the pre-built session → islogged = true.
 *
 * Falls back silently (returns) to standard LMS PIN auth when:
 *   - LDAP is not configured
 *   - LDAP bind fails (wrong password or non-AD user)
 *   - No matching LMS customer found for the AD e-mail
 *
 * Configuration (lms.ini):
 *   [WeKrwiITLDAPAuthPass]
 *   host            = ldaps://ldap.example.org ; LDAP server URI
 *   port            = 636
 *   base_dn         = DC=ad,DC=example,DC=org
 *   bind_dn_suffix  = @ad.example.org          ; appended to bare login → UPN
 *   ldap_mail_attr  = mail                     ; LDAP attribute with e-mail
 *   tls_require_cert = demand                  ; never | allow | demand (default: demand, fail-closed)
 *   ; allowed_status =                         ; comma-sep ints; empty = all
 *   ; require_group  =                         ; see companion admin handler for the equivalent operator-side control
 *
 * Security notes (2026-08-31 audit, 3 modeli, runda 6):
 *   - Ten plugin CELOWO odmawia auto-loginu, gdy w userpanel.twofactor_auth_type
 *     skonfigurowane jest 2FA — pisze bezpośrednio do up_sessions z pominięciem
 *     Session::__construct(), więc nie potrafi bezpiecznie odtworzyć kroku SMS/e-mail
 *     bez duplikowania core'owej logiki wysyłki OTP. Klient z 2FA loguje się przez
 *     standardowy PIN, LDAP zostaje pominięte (fallback), nie obejściem 2FA.
 *   - Login CSRF: formularz loginform w core userpanel nie ma tokenu CSRF (ten sam
 *     brak co przy zwykłym PIN) — NIE naprawione tutaj, wymaga zmiany szablonu core,
 *     poza zakresem plugin-only.
 *   - Throttle liczony jest po $_SERVER['REMOTE_ADDR'], NIE po X-Forwarded-For:
 *     zaufanie do XFF (który jest w pełni kontrolowany przez klienta, dopóki brak
 *     skonfigurowanego trusted-proxy) pozwoliłoby trywialnie obejść throttle przez
 *     rotację nagłówka — to gorsza luka niż jeden współdzielony bucket za reverse
 *     proxy. Jeśli instalacja stoi za proxy, prawidłowy client-IP MUSI być ustawiony
 *     na poziomie web servera (np. nginx `set_real_ip_from`/`real_ip_header`), nie
 *     w tym pluginie. Throttle to dwa atomowe sloty czasowe (150s/300s TTL,
 *     apcu_add+apcu_inc — atomowość jest tu celowa, bo fetch-then-store gubi
 *     inkrementy pod równoległymi żądaniami), sumowane przy odczycie jako
 *     przybliżone okno kroczące. Po udanym LOGOWANIU (nie samym bindzie — patrz
 *     niżej) resetuje się WYŁĄCZNIE licznik per-(IP+login), oba sloty; licznik
 *     per-IP musi przetrwać sukces, bo chroni przed password-spray.
 *   - Reset licznika następuje dopiero przy PEŁNYM sukcesie (klient znaleziony
 *     jednoznacznie, brak 2FA, reCAPTCHA OK) — nie przy samym udanym ldap_bind().
 *     Konto AD bez dopasowanego klienta LMS, z niejednoznacznym mailem, albo
 *     trafiające na 2FA nigdy nie resetuje własnego bucketu per-login; to
 *     akceptowalne (taki bind i tak nie prowadzi do sesji), tylko celowo NIE
 *     jest to "self-heal przy każdym udanym bindzie".
 *   - Blok tymczasowy (`enabled==0 AND failedlogindate<10min`) replikuje DOKŁADNIE
 *     logikę core (userpanel/lib/Session.class.php:446-448, 536-591): `enabled` w
 *     up_customers to WYŁĄCZNIE licznik nieudanych prób (2→1→0), nie istnieje osobna
 *     flaga "konto trwale wyłączone przez admina" w tej tabeli — core sam resetuje
 *     stary lockout tym samym warunkiem. Zweryfikowane czytaniem core, nie zgadywane.
 *   - Model zaufania: e-mail do mapowania klienta pochodzi z atrybutu `mail`
 *     uwierzytelnionego w AD konta. Kontrola dostępu do panelu klienta jest więc
 *     tak silna, jak kontrola nad edycją własnego atrybutu `mail` w AD (self-service
 *     AD change bez admina = potencjalne przejęcie konta klienta o tym samym mailu).
 *     To świadome zaufanie do katalogu AD, nie błąd w tym pluginie — admin
 *     wdrażający musi mieć to na uwadze przy konfiguracji uprawnień w AD.
 *
 * Activation (lms.ini):
 *   [phpui]
 *   plugins = ... WeKrwiITLDAPAuthPass WeKrwiITLDAPAuthPassUP
 *
 *   Both names are required — they are two separate plugins (new-style admin
 *   handler + this old-style userpanel script) and LMSPluginManager loads each
 *   independently by its own basename. Listing only "WeKrwiITLDAPAuthPass"
 *   enables the admin-panel LDAP handler but leaves this userpanel file
 *   inactive with no error or log line (audit 2026-09-02, 3 models).
 */

// ── Guard: userpanel context only ────────────────────────────────────────────
if (!defined('USERPANEL_DIR')) {
    return;
}

// ── Guard: only act on login form POST ───────────────────────────────────────
if (empty($_POST['loginform']['login']) || empty($_POST['loginform']['pwd'])) {
    return;
}

$_wkldap_login  = trim($_POST['loginform']['login']);
$_wkldap_passwd = $_POST['loginform']['pwd'];
$_wkldap_login_safe = str_replace(["\r", "\n"], '', $_wkldap_login); // log-injection guard

// ── Read config ───────────────────────────────────────────────────────────────
$_wkldap_host      = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.host', '');
$_wkldap_port      = (int) ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.port', 636);
$_wkldap_base_dn   = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.base_dn', '');
$_wkldap_suffix    = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.bind_dn_suffix', '');
$_wkldap_mail_attr = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.ldap_mail_attr', 'mail');
$_wkldap_tls       = strtolower(ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.tls_require_cert', 'demand'));

if (empty($_wkldap_host) || empty($_wkldap_base_dn)) {
    return;
}

if (!function_exists('ldap_connect')) {
    writesyslog('WeKrwiITLDAPAuthPass: PHP ldap extension not available', LOG_ERR);
    return;
}

// ── TLS certificate policy (global, before connect) ──────────────────────────
$_wkldap_tls_map = [
    'never'  => LDAP_OPT_X_TLS_NEVER,
    'allow'  => LDAP_OPT_X_TLS_ALLOW,
    'demand' => LDAP_OPT_X_TLS_DEMAND,
];
ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, $_wkldap_tls_map[$_wkldap_tls] ?? LDAP_OPT_X_TLS_DEMAND);

// ── Throttle bind attempts (independent of reCAPTCHA — see below) ────────────
// reCAPTCHA is checked LAST (right before session creation) so its single-use
// token isn't burned on every fallback path. That means an unauthenticated bot
// can otherwise reach ldap_bind() freely, ignoring reCAPTCHA entirely, and use
// this plugin as a password-spray oracle against AD. This gate closes that: a
// per-IP+login failure counter (APCu, best-effort — fails open if unavailable,
// AD's own account lockout remains the backstop).
// Two independent counters: per (IP+login) catches credential-stuffing a single
// account; per IP alone (higher threshold) catches password-spray, where one
// guessed password is tried against many different logins — a per-login key
// never accumulates for that pattern.
// Two-slot sliding window (150s each, 300s TTL per slot — self-expiring, no
// cron/GC needed): counting is apcu_add+apcu_inc, both atomic under APCu's
// own lock, so concurrent requests never lose an increment (unlike a
// fetch-then-store read-modify-write, which undercounts when requests race).
// Reading sums the current + previous slot, so a failure never falls out of
// the window sooner than ~150-300s after it happened, unlike a single fixed
// TTL counter that resets to zero on a schedule independent of attack activity.
// Normalize to the bare account name (strip UPN suffix) so "user" and
// "user@ad.example.org" — the same AD object — share one bucket instead of
// splitting the per-login threshold across two. Hashed (not raw) and length-
// bounded so an attacker can't grow the APCu keyspace with arbitrary login text.
$_wkldap_login_norm = strtolower(
    strpos($_wkldap_login_safe, '@') !== false ? strstr($_wkldap_login_safe, '@', true) : $_wkldap_login_safe
);
$_wkldap_slot              = intdiv(time(), 150);
$_wkldap_throttle_base     = 'wkldap_up:' . ($_SERVER['REMOTE_ADDR'] ?? '') . ':' . sha1($_wkldap_login_norm);
$_wkldap_throttle_ip_base  = 'wkldap_up_ip:' . ($_SERVER['REMOTE_ADDR'] ?? '');
$_wkldap_throttle_key      = $_wkldap_throttle_base . ':' . $_wkldap_slot;
$_wkldap_throttle_key_prev = $_wkldap_throttle_base . ':' . ($_wkldap_slot - 1);
$_wkldap_throttle_ip_key      = $_wkldap_throttle_ip_base . ':' . $_wkldap_slot;
$_wkldap_throttle_ip_key_prev = $_wkldap_throttle_ip_base . ':' . ($_wkldap_slot - 1);
if (function_exists('apcu_fetch')) {
    $_wkldap_fails    = (int) apcu_fetch($_wkldap_throttle_key) + (int) apcu_fetch($_wkldap_throttle_key_prev);
    $_wkldap_ip_fails = (int) apcu_fetch($_wkldap_throttle_ip_key) + (int) apcu_fetch($_wkldap_throttle_ip_key_prev);
    if ($_wkldap_fails >= 5 || $_wkldap_ip_fails >= 30) {
        writesyslog(
            'WeKrwiITLDAPAuthPass: throttled (too many failed binds) for '
                . substr($_wkldap_login_safe, 0, 3) . '*** from ' . ($_SERVER['REMOTE_ADDR'] ?? ''),
            LOG_WARNING
        );
        return;
    }
} else {
    writesyslog('WeKrwiITLDAPAuthPass: APCu unavailable — bind throttle disabled', LOG_WARNING);
}

// ── Connect ───────────────────────────────────────────────────────────────────
$_wkldap_uri  = rtrim($_wkldap_host, '/') . ':' . $_wkldap_port;
$_wkldap_conn = @ldap_connect($_wkldap_uri);
if (!$_wkldap_conn) {
    writesyslog('WeKrwiITLDAPAuthPass: cannot connect to ' . $_wkldap_uri, LOG_WARNING);
    return;
}
ldap_set_option($_wkldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($_wkldap_conn, LDAP_OPT_REFERRALS, 0);
ldap_set_option($_wkldap_conn, LDAP_OPT_NETWORK_TIMEOUT, 3);

// ── Bind (UPN format: login@domain or full e-mail) ────────────────────────────
$_wkldap_bind_dn = (strpos($_wkldap_login, '@') !== false)
    ? $_wkldap_login
    : ($_wkldap_login . $_wkldap_suffix);

$_wkldap_bound = @ldap_bind($_wkldap_conn, $_wkldap_bind_dn, $_wkldap_passwd);
if (!$_wkldap_bound) {
    // Log only a masked prefix — the login field is user-typed and can contain
    // a mistyped password; never write the full raw value to syslog.
    writesyslog(
        'WeKrwiITLDAPAuthPass: bind failed for ' . substr($_wkldap_login_safe, 0, 3) . '***: '
            . ldap_error($_wkldap_conn),
        LOG_INFO
    );
    @ldap_close($_wkldap_conn);
    if (function_exists('apcu_add')) {
        // Atomic (apcu_inc holds APCu's own lock) — no lost increments under
        // concurrent requests. Slot self-expires via its own 300s TTL. The
        // apcu_inc $ttl argument matters: if the key vanished between add and
        // inc (evicted, or deleted by a concurrent success-reset), inc alone
        // recreates it with ttl=0 — i.e. permanent — which for the per-IP key
        // (never reset on success) would lock that IP out until FPM restart.
        apcu_add($_wkldap_throttle_key, 0, 300);
        apcu_inc($_wkldap_throttle_key, 1, $_wkldap_inc_ok, 300);
        apcu_add($_wkldap_throttle_ip_key, 0, 300);
        apcu_inc($_wkldap_throttle_ip_key, 1, $_wkldap_ip_inc_ok, 300);
    }
    return; // fall through to standard PIN auth
}

// ── Fetch mail attribute using the authenticated session ──────────────────────
$_wkldap_mail = null;
$_wkldap_sam  = (strpos($_wkldap_login, '@') !== false)
    ? strstr($_wkldap_login, '@', true)
    : $_wkldap_login;

$_wkldap_filter = '(sAMAccountName=' . ldap_escape($_wkldap_sam, '', LDAP_ESCAPE_FILTER) . ')';
$_wkldap_search = @ldap_search(
    $_wkldap_conn,
    $_wkldap_base_dn,
    $_wkldap_filter,
    [strtolower($_wkldap_mail_attr)],
    0, 1, 3
);
if ($_wkldap_search) {
    $_wkldap_entries = @ldap_get_entries($_wkldap_conn, $_wkldap_search);
    $_wkldap_attr_lc = strtolower($_wkldap_mail_attr);
    if ($_wkldap_entries && $_wkldap_entries['count'] > 0
        && isset($_wkldap_entries[0][$_wkldap_attr_lc][0])
    ) {
        $_wkldap_mail = strtolower(trim($_wkldap_entries[0][$_wkldap_attr_lc][0]));
    }
}
@ldap_close($_wkldap_conn);

// ── Determine e-mail for customer lookup ─────────────────────────────────────
// WYS-2 (2026-08-06 audit): the lookup key MUST come from the authenticated
// LDAP entry's own `mail` attribute, never from the raw POSTed login. A raw
// login containing "@" is attacker-controlled text — trusting it as the
// lookup e-mail let an attacker with ANY valid AD credential log in as the
// LMS customer whose contact e-mail happened to match that string, as long
// as their own AD account's `mail` attribute was simply absent.
$_wkldap_lookup = $_wkldap_mail;
if (empty($_wkldap_lookup)) {
    writesyslog(
        'WeKrwiITLDAPAuthPass: auth OK for ' . $_wkldap_login_safe . ' but cannot determine e-mail',
        LOG_WARNING
    );
    return;
}

// ── Find LMS customer by e-mail ───────────────────────────────────────────────
$_wkldap_status_raw = ConfigHelper::getConfig('WeKrwiITLDAPAuthPass.allowed_status', '', true);
$_wkldap_status     = empty($_wkldap_status_raw)
    ? null
    : array_map('intval', preg_split('/[\s,;]+/', $_wkldap_status_raw, -1, PREG_SPLIT_NO_EMPTY));

$_wkldap_candidates = $DB->GetCol(
    'SELECT DISTINCT c.id FROM customers c
     JOIN customercontacts cc ON cc.customerid = c.id
     WHERE c.deleted = 0
       AND LOWER(cc.contact) = ?
       AND (cc.type & ?) > 0
       AND (cc.type & ?) = 0
       ' . (!empty($_wkldap_status) ? 'AND c.status IN (' . implode(',', $_wkldap_status) . ')' : '') . '
     ORDER BY c.id',
    [
        $_wkldap_lookup,
        CONTACT_EMAIL | CONTACT_INVOICES | CONTACT_NOTIFICATIONS,
        CONTACT_DISABLED,
    ]
);

if (empty($_wkldap_candidates)) {
    writesyslog(
        'WeKrwiITLDAPAuthPass: auth OK for ' . $_wkldap_login_safe
            . ' but no LMS customer with e-mail=' . $_wkldap_lookup,
        LOG_WARNING
    );
    return;
}

if (count($_wkldap_candidates) > 1) {
    writesyslog(
        'WeKrwiITLDAPAuthPass: auth OK for ' . $_wkldap_login_safe
            . ' but e-mail=' . $_wkldap_lookup . ' matches ' . count($_wkldap_candidates)
            . ' customers (' . implode(',', $_wkldap_candidates) . ') — refusing ambiguous login',
        LOG_ERR
    );
    return;
}

$_wkldap_cid = $_wkldap_candidates[0];

// ── Refuse auto-login when userpanel 2FA is configured ───────────────────────
// This plugin writes up_sessions directly, bypassing Session::__construct(),
// which is where session_authcoderequired is set and the SMS/e-mail OTP is
// actually sent. Reimplementing that flow here would duplicate core logic
// with no test coverage; instead we decline the shortcut and fall through to
// standard PIN auth, which still enforces 2FA correctly.
if (ConfigHelper::getConfig('userpanel.twofactor_auth_type', '', true) !== '') {
    writesyslog(
        'WeKrwiITLDAPAuthPass: auth OK for ' . $_wkldap_login_safe . ' (customer ' . $_wkldap_cid
            . ') but userpanel 2FA is enabled — refusing LDAP auto-login, falling back to PIN+2FA',
        LOG_INFO
    );
    return;
}

// ── Check temporary block ─────────────────────────────────────────────────────
$_wkldap_up = $DB->GetRow('SELECT * FROM up_customers WHERE customerid = ?', [$_wkldap_cid]);
if (!empty($_wkldap_up)
    && $_wkldap_up['enabled'] == 0
    && time() - $_wkldap_up['failedlogindate'] < 600
) {
    writesyslog('WeKrwiITLDAPAuthPass: customer ' . $_wkldap_cid . ' is temporarily blocked', LOG_WARNING);
    return;
}

// ── reCAPTCHA, mirroring Session::VerifyPassword()'s gate ────────────────────
// This plugin runs before Session exists, so ValidateRecaptchaResponse() (private,
// on Session) isn't reachable — the check is replicated here rather than skipped,
// so the LDAP shortcut can't be used to bypass the panel's anti-bruteforce control.
// Deliberately placed LAST, right before we commit to auto-login: the Google
// token is single-use, and every earlier return above falls through to the
// standard PIN form, which performs its own fresh verification of the same
// POST — checking here first would burn the token and make that verification
// fail with "timeout-or-duplicate" on every normal (non-LDAP) login attempt.
$_wkldap_recaptcha_key = ConfigHelper::getConfig('userpanel.google_recaptcha_sitekey');
if (!empty($_wkldap_recaptcha_key)) {
    if (empty($_POST['g-recaptcha-response']) || !is_string($_POST['g-recaptcha-response'])
        || !function_exists('curl_init')
    ) {
        return; // fall through to standard login, which enforces reCAPTCHA itself
    }
    $_wkldap_ch = curl_init('https://www.google.com/recaptcha/api/siteverify');
    curl_setopt_array($_wkldap_ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => ConfigHelper::getConfig('userpanel.google_recaptcha_secret'),
            'response' => $_POST['g-recaptcha-response'],
            'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
        ]),
    ]);
    $_wkldap_recaptcha_res = curl_exec($_wkldap_ch);
    curl_close($_wkldap_ch);
    $_wkldap_recaptcha_ok = $_wkldap_recaptcha_res !== false
        && ($_wkldap_recaptcha_json = json_decode($_wkldap_recaptcha_res, true)) !== null
        && !empty($_wkldap_recaptcha_json['success']);
    if (!$_wkldap_recaptcha_ok) {
        return; // fall through to standard login (its own reCAPTCHA check will need a fresh token)
    }
}

// ── Create up_sessions row ────────────────────────────────────────────────────
// Replicates Session::_createSession() + Session::makeVData()
$_wkldap_sid = bin2hex(random_bytes(32));
$_wkldap_now = time();
$_wkldap_ip  = str_replace('::ffff:', '', $_SERVER['REMOTE_ADDR'] ?? '');

$_wkldap_vdata = [];
foreach (['REMOTE_ADDR','REMOTE_HOST','HTTP_USER_AGENT','HTTP_VIA','HTTP_X_FORWARDED_FOR','SERVER_NAME','SERVER_PORT'] as $_k) {
    if (isset($_SERVER[$_k])) {
        $_wkldap_vdata[$_k] = $_SERVER[$_k];
    }
}

// Session restores $this->login and $this->id from these keys on next request.
$_wkldap_content = [
    'session_id'    => (int) $_wkldap_cid,
    'session_login' => $_wkldap_login,
];

$DB->Execute(
    'INSERT INTO up_sessions (id, customerid, ctime, mtime, atime, vdata, content)
     VALUES (?, ?, ?, ?, ?, ?, ?)',
    [
        $_wkldap_sid,
        (int) $_wkldap_cid,
        $_wkldap_now,
        $_wkldap_now,
        $_wkldap_now,
        serialize($_wkldap_vdata),
        serialize($_wkldap_content),
    ]
);

// ── Update up_customers (login stats) ────────────────────────────────────────
if (!empty($_wkldap_up)) {
    $DB->Execute(
        'UPDATE up_customers SET lastlogindate=?, lastloginip=?, enabled=3 WHERE customerid=?',
        [$_wkldap_now, $_wkldap_ip, $_wkldap_cid]
    );
} else {
    $DB->Execute(
        "INSERT INTO up_customers (customerid, lastlogindate, lastloginip, failedlogindate, failedloginip, enabled)
         VALUES (?, ?, ?, 0, '', 3)",
        [$_wkldap_cid, $_wkldap_now, $_wkldap_ip]
    );
}

// Successful login clears only the per-(IP+login) throttle counter: a
// legitimate user who mistyped a password a few times shouldn't stay locked
// out for the full TTL after finally succeeding. The per-IP counter MUST
// survive: it exists specifically to catch password-spray, and resetting it
// on success would let anyone with one valid AD credential (not necessarily
// matching an LMS customer at all, since ldap_bind succeeds before lookup)
// wipe it every ~29 attempts, making the threshold unenforceable against
// exactly the attack it targets.
if (function_exists('apcu_delete')) {
    apcu_delete($_wkldap_throttle_key);
    apcu_delete($_wkldap_throttle_key_prev);
}

writesyslog(
    'WeKrwiITLDAPAuthPass: LDAP auth success login=' . $_wkldap_login_safe
        . ' email=' . $_wkldap_lookup . ' customer_id=' . $_wkldap_cid,
    LOG_INFO
);

// ── Set USID cookie and redirect ──────────────────────────────────────────────
// Browser re-requests the same URL; Session::_restoreSession() picks up the
// session row and sets islogged = true without any changes to Session.class.php.
$_wkldap_secure = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
setcookie('USID', $_wkldap_sid, [
    'expires'  => 0,
    'path'     => '/',
    'secure'   => $_wkldap_secure,
    'httponly' => true,
    'samesite' => 'Lax',
]);

// Redirect must stay same-origin: REQUEST_URI is attacker-controlled and a
// leading "//host" or "/\host" makes some browsers treat it as protocol-relative.
$_wkldap_redirect = $_SERVER['REQUEST_URI'] ?? '/';
if (!preg_match('#^/(?!/|\\\\)#', $_wkldap_redirect)) {
    $_wkldap_redirect = '/';
}
header('Location: ' . $_wkldap_redirect);
exit;
