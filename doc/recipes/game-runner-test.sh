#!/bin/bash
# A failed referee or player must end the tournament runner and expose its stderr.
set -euo pipefail
: "${RECIPES_DIR:?}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
cat > "$work/bin/lua5.4" <<'EOF'
#!/bin/bash
if [ "$1" = -e ]; then
    echo initial-hash
elif [ "$2" = referee ]; then
    if [ "$FAIL_ROLE" = referee ]; then
        echo 'deliberate referee failure' >&2
        exit 42
    elif [ "$FAIL_ROLE" = early-referee ]; then
        exit 0
    fi
    exec sleep 60
else
    if [ "$FAIL_ROLE" = early-player ]; then exit 0; fi
    echo 'deliberate player failure' >&2
    exit 43
fi
EOF
cat > "$work/bin/netstat" <<'EOF'
#!/bin/bash
if [ "$1" = -ntl ] && [[ "$FAIL_ROLE" = *player ]]; then
    echo 'tcp 127.0.0.1:8097 LISTEN'
fi
EOF
chmod +x "$work/bin/lua5.4" "$work/bin/netstat"
for role in referee player early-referee early-player; do
    status=0
    FAIL_ROLE=$role PATH="$work/bin:$PATH" timeout 10 bash "$RECIPES_DIR/prt-repeat-test.sh" \
        "$work/template" "$work/inputs" "$work/recording" > "$work/$role.log" 2>&1 || status=$?
    case $role in
        referee) expected=42; message='deliberate referee failure';;
        player) expected=43; message='deliberate player failure';;
        *) expected=1; message='Child exited before initial subscriptions closed';;
    esac
    if [ "$status" -ne "$expected" ]; then
        cat "$work/$role.log" >&2
        echo "Expected $role exit $expected, got $status" >&2
        exit 1
    fi
    grep -q "$message" "$work/$role.log"
done
echo 'game-runner-test: ok'
