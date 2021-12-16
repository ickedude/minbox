#!/bin/sh

if [ -n "$SLOW_ENTRY" ]; then
	sleep "$SLOW_ENTRY"
fi
exec "$@"
