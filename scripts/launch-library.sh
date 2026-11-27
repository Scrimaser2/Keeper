#!/bin/bash

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/launch-library.sh"

if command -v launchctl >/dev/null 2>&1; then
	SESSION_ACCESS_CODE="$(launchctl getenv LIBRARY_ACCESS_CODE 2>/dev/null || true)"
	if [ -n "$SESSION_ACCESS_CODE" ]; then
		LIBRARY_ACCESS_CODE="$SESSION_ACCESS_CODE"
		export LIBRARY_ACCESS_CODE
	fi
fi

if [ ! -t 0 ] || [ ! -t 1 ]; then
	SCRIPT_COMMAND="/bin/bash $(printf '%q' "$SCRIPT_PATH")"
	if [ "${LIBRARY_ACCESS_CODE+x}" = x ]; then
		SCRIPT_COMMAND="LIBRARY_ACCESS_CODE=$(printf '%q' "$LIBRARY_ACCESS_CODE") $SCRIPT_COMMAND"
	fi
	/usr/bin/osascript - "$SCRIPT_COMMAND" <<'APPLESCRIPT'
on run argv
	 tell application "Terminal"
		 activate
		 do script (item 1 of argv)
	 end tell
end run
APPLESCRIPT
	exit 0
fi

pause_before_exit() {
	printf '\nPress any key to exit.'
	IFS= read -r -s -n 1 _ </dev/tty || true
	printf '\n'
}

read_secret() {
	local prompt="$1"
	local destination="$2"
	printf '%s' "$prompt"
	IFS= read -r -s "$destination" </dev/tty || printf -v "$destination" '%s' ""
	printf '\n'
}

normalize_code() {
	printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

APP_EXECUTABLE="$SCRIPT_DIR/../dist/Library.app/Contents/MacOS/Library"
if [ ! -x "$APP_EXECUTABLE" ]; then
	printf 'Application not found: %s\n' "$APP_EXECUTABLE"
	pause_before_exit
	exit 1
fi

if [ "${LIBRARY_ACCESS_CODE+x}" = x ]; then
	CURRENT_ACCESS_CODE="$LIBRARY_ACCESS_CODE"
	read_secret 'Current access code: ' CURRENT_CODE_INPUT
	if [ -z "$CURRENT_ACCESS_CODE" ] || [ "$(normalize_code "$CURRENT_CODE_INPUT")" != "$(normalize_code "$CURRENT_ACCESS_CODE")" ]; then
		printf 'Action unavailable: the current access code is incorrect.\n'
		pause_before_exit
		exit 1
	fi
	read_secret 'New access code (leave empty to keep current): ' NEW_ACCESS_CODE
	if [ -n "$NEW_ACCESS_CODE" ]; then
		read_secret 'Confirm new access code: ' CONFIRMED_ACCESS_CODE
		if [ "$(normalize_code "$NEW_ACCESS_CODE")" != "$(normalize_code "$CONFIRMED_ACCESS_CODE")" ]; then
			printf 'Action unavailable: the new access codes do not match.\n'
			pause_before_exit
			exit 1
		fi
		LIBRARY_ACCESS_CODE="$NEW_ACCESS_CODE"
		UPDATE_SESSION_CODE=1
	else
		LIBRARY_ACCESS_CODE="$CURRENT_ACCESS_CODE"
	fi
else
	read_secret 'Enter access code: ' LIBRARY_ACCESS_CODE
	UPDATE_SESSION_CODE=1
fi

if [ -z "$LIBRARY_ACCESS_CODE" ]; then
	printf 'Action unavailable: no access code was entered.\n'
	pause_before_exit
	exit 1
fi

if [ "${UPDATE_SESSION_CODE:-0}" = 1 ] && command -v launchctl >/dev/null 2>&1 && ! launchctl setenv LIBRARY_ACCESS_CODE "$LIBRARY_ACCESS_CODE"; then
	printf 'Action unavailable: could not update the user session environment.\n'
	pause_before_exit
	exit 1
fi

export LIBRARY_ACCESS_CODE
exec "$APP_EXECUTABLE"
