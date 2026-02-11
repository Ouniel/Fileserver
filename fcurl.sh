#!/bin/bash
# fcurl.sh - File Server Curl Helper for Linux/macOS
# Usage: ./fcurl.sh <URL>
# Example: ./fcurl.sh http://127.0.0.1:8080/test.txt
#          ./fcurl.sh http://127.0.0.1:8080/

if [ $# -lt 1 ]; then
    echo "Usage: $0 <URL>"
    echo "Example: $0 http://127.0.0.1:8080/test.txt"
    exit 1
fi

URL="$1"

# Parse URL to get host and path
# Format: http://host:port/path or http://host:port/path/
PROTOCOL=$(echo "$URL" | cut -d'/' -f1)
HOST_PORT=$(echo "$URL" | cut -d'/' -f3)
PATH_PART=$(echo "$URL" | cut -d'/' -f4-)

# Check if directory (ends with / or no extension)
IS_DIR=0

# Check if ends with /
if [[ "$URL" == */ ]]; then
    IS_DIR=1
fi

# If not ends with /, check if has file extension
if [ $IS_DIR -eq 0 ]; then
    # Extract the last part of the path
    LAST_PART=$(basename "$PATH_PART")
    
    # Check if last part contains dot (has extension)
    if [[ ! "$LAST_PART" =~ \. ]]; then
        # No extension, treat as directory
        IS_DIR=1
        # Add trailing slash for consistency
        PATH_PART="${PATH_PART}/"
    fi
fi

# Build sign URL by adding list/ or download/ prefix
if [ $IS_DIR -eq 1 ]; then
    SIGN_URL="http://${HOST_PORT}/list/${PATH_PART}"
else
    SIGN_URL="http://${HOST_PORT}/download/${PATH_PART}"
fi

# Call sign.exe and get signed URL
SIGNED_URL=$(./sign "$SIGN_URL" 2>/dev/null | grep "^http://")

if [ -z "$SIGNED_URL" ]; then
    echo "Error: Failed to generate signed URL"
    exit 1
fi

# Execute curl
if [ $IS_DIR -eq 1 ]; then
    curl "$SIGNED_URL"
else
    curl -OJ "$SIGNED_URL"
fi
