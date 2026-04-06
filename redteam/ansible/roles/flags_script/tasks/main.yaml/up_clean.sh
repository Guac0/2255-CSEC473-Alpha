#!/usr/bin/env bash
# keep_contents.sh - overwrite given files with "andrew niebur" every 9s for 10 minutes
# Usage: keep_contents.sh /path/to/file1 /path/to/file2 ...
# Example to run detached:
#   nohup /usr/local/bin/keep_contents.sh /etc/myconf /tmp/testfile &

set -euo pipefail

# Interval in seconds between writes
INTERVAL=9
# Total run time in seconds (10 minutes = 600s)
DURATION=600
# Content to write
CONTENT='andrew niebur'

# Check that at least one file is given
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 /path/to/file1 [/path/to/file2 ...]"
  exit 2
fi

# Resolve absolute start time
START=$(date +%s)
END=$((START + DURATION))

# Optional: store files in array, skip duplicates
declare -a FILES=()
for f in "$@"; do
  # Optional: expand ~ and relative path
  FILES+=("$(realpath -m "$f")")
done

# Main loop
while [ "$(date +%s)" -lt "$END" ]; do
  for file in "${FILES[@]}"; do
    # Ensure directory exists; if not, skip with warning
    dir=$(dirname "$file")
    if [ ! -d "$dir" ]; then
      echo "Skipping $file: directory $dir does not exist" >&2
      continue
    fi

    # If file exists and is writable by current user, overwrite in-place.
    # If file does not exist, create it with current user's ownership.
    # We write atomically by writing to a temp file in the same directory then renaming.
    tmpfile="$(mktemp "${dir}/.tmp.XXXXXX")" || { echo "Failed to create temp file in $dir" >&2; continue; }
    printf '%s\n' "$CONTENT" > "$tmpfile"
    # Preserve mode of existing file if present
    if [ -e "$file" ]; then
      # Copy file mode from original to temp
      chmod --reference="$file" "$tmpfile" || true
      # Preserve owner/group if running as root; rename will keep owner/group if same FS
    fi
    mv -f "$tmpfile" "$file" || { echo "Failed to move $tmpfile to $file" >&2; rm -f "$tmpfile"; continue; }
  done
  now=$(date +%s)
  if [ "$now" -ge "$END" ]; then
    break
  fi
  remaining=$((END - now))
  if [ "$remaining" -lt "$INTERVAL" ]; then
    sleep "$remaining"
  else
    sleep "$INTERVAL"
  fi
done

exit 0
