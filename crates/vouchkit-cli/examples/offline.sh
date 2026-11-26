#!/bin/sh
# Demonstrate issuing and verifying an offline license with a disposable key.
set -eu

vouch_bin=${VOUCH:-vouch}
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

"$vouch_bin" keygen --kind master --key-id 1 --out-dir "$work_dir" --insecure-plaintext
"$vouch_bin" issue --key "$work_dir/master.key" --class standalone \
    --product demo --subject "Local example" --tier 1 \
    --feature-slots 10,64 --max-version 2.x.x --format file \
    --ledger "$work_dir/issued.jsonl" --out "$work_dir/license.vk"
"$vouch_bin" verify "$work_dir/license.vk" --pubkey "$work_dir/master.pub" \
    --product demo --app-version 2.4.0
