package io.github.socgabrielcardoso.traceguard.domain;

import java.util.Locale;
import java.util.Map;

public enum EventType {
    AUTH_FAILURE,
    AUTH_SUCCESS,
    ACCOUNT_LOCKOUT,
    PRIVILEGE_CHANGE,
    SECURITY_CONTROL_DISABLED,
    PROCESS_EXECUTION,
    CONFIGURATION_CHANGE,
    UNKNOWN;

    private static final Map<String, EventType> ALIASES = Map.ofEntries(
            Map.entry("LOGIN_FAILURE", AUTH_FAILURE),
            Map.entry("FAILED_LOGIN", AUTH_FAILURE),
            Map.entry("LOGON_FAILURE", AUTH_FAILURE),
            Map.entry("LOGIN_SUCCESS", AUTH_SUCCESS),
            Map.entry("SUCCESSFUL_LOGIN", AUTH_SUCCESS),
            Map.entry("LOGON_SUCCESS", AUTH_SUCCESS),
            Map.entry("USER_LOCKED", ACCOUNT_LOCKOUT),
            Map.entry("ADMIN_GRANTED", PRIVILEGE_CHANGE),
            Map.entry("GROUP_MEMBERSHIP_CHANGE", PRIVILEGE_CHANGE),
            Map.entry("ANTIVIRUS_DISABLED", SECURITY_CONTROL_DISABLED),
            Map.entry("FIREWALL_DISABLED", SECURITY_CONTROL_DISABLED),
            Map.entry("AUDIT_DISABLED", SECURITY_CONTROL_DISABLED),
            Map.entry("PROCESS_START", PROCESS_EXECUTION),
            Map.entry("CONFIG_CHANGE", CONFIGURATION_CHANGE)
    );

    public static EventType from(String value) {
        if (value == null || value.isBlank()) {
            return UNKNOWN;
        }
        String normalized = value.trim()
                .toUpperCase(Locale.ROOT)
                .replace('-', '_')
                .replace(' ', '_');
        try {
            return valueOf(normalized);
        } catch (IllegalArgumentException ignored) {
            return ALIASES.getOrDefault(normalized, UNKNOWN);
        }
    }
}
