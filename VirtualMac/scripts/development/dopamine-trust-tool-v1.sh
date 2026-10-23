# Sourced by the package configure script after the private metadata log exists.
# Use the jailbreak's own binary and libraries; never copy or replace basebin.
vm27_read_trust_cache() {
    "$vm27_trust_tool" trustcache info 2>> "$log"
}

vm27_select_trust_tool() {
    vm27_jbroot=$(realpath /var/jb) || return 1
    vm27_trust_tool=
    for vm27_candidate in /var/jb/basebin/jbctl /var/jb/usr/bin/jbctl; do
        [ -x "$vm27_candidate" ] || continue
        vm27_resolved=$(realpath "$vm27_candidate") || continue
        # The symlink installed by dopamine-basebin-link resolves here. Executing
        # the canonical file also gives @loader_path its actual basebin directory.
        [ "$vm27_resolved" = "$vm27_jbroot/basebin/jbctl" ] || continue
        [ -f "$vm27_resolved" ] && [ ! -L "$vm27_resolved" ] || continue
        vm27_trust_tool=$vm27_resolved
        break
    done
    if [ -z "$vm27_trust_tool" ]; then
        printf 'trust-tool-error=no-official-basebin-jbctl\n' >> "$log"
        return 1
    fi
    printf 'trust-tool=%s\n' "$vm27_trust_tool" >> "$log"
}

vm27_query_trust_cache() {
    vm27_status=0
    trusted_raw=$(vm27_read_trust_cache) || vm27_status=$?
    printf 'trust-info-exit=%s\n' "$vm27_status" >> "$log"
    [ "$vm27_status" = 0 ] || return "$vm27_status"
    # Upstream jbctl can return 0 even when its service query failed. Empty
    # stdout must not be mistaken for an empty but functioning trust cache.
    if ! printf '%s\n' "$trusted_raw" | awk '
        /^Jailbreak Trustcache [0-9]+ / {seen=1}
        END {exit !seen}'; then
        printf 'trust-tool-error=no-service-reply\n%s\n' "$trusted_raw" >> "$log"
        return 1
    fi
}
