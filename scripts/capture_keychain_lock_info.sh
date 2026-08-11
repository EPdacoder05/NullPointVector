#!/bin/bash
# Debug session aa4ecf — capture why sharingd/iCloudHelper ask for login keychain on wake.
set +e
LOG="/Users/ep/DevProjects/Yahoo_Phish/.cursor/debug-aa4ecf.log"
KC="$HOME/Library/Keychains/login.keychain-db"

emit() {
  python3 - "$1" "$2" "$3" <<'PY'
import json,sys,time
hid,msg,data=sys.argv[1],sys.argv[2],sys.argv[3]
rec={"sessionId":"aa4ecf","timestamp":int(time.time()*1000),"hypothesisId":hid,"location":"scripts/capture_keychain_lock_info.sh","message":msg,"data":json.loads(data),"runId":"repro-wake"}
open("/Users/ep/DevProjects/Yahoo_Phish/.cursor/debug-aa4ecf.log","a").write(json.dumps(rec)+"\n")
print(f"[{hid}] {msg}: {data[:200]}")
PY
}

echo "=== H-D: NullPoint items in login keychain? ==="
NP=$(security find-generic-password -s "com.nullpoint.guard.auth" 2>&1)
emit D nullpoint_search "$(python3 -c 'import json,sys; print(json.dumps({"rc":0 if "svce" in sys.argv[1] else 44,"out":sys.argv[1][:300]}))' "$NP")"

echo "=== H-B: login keychain lock settings (enter keychain password if Terminal asks) ==="
INFO=$(security show-keychain-info "$KC" 2>&1)
echo "$INFO"
emit B show_keychain_info "$(python3 -c 'import json,sys; print(json.dumps({"info":sys.argv[1]}))' "$INFO")"

echo "=== H-C: sharingd AutoUnlock in last 15m ==="
AU=$(log show --last 15m --style compact --predicate 'process == "sharingd" AND (eventMessage CONTAINS "AutoUnlock" OR eventMessage CONTAINS "SecItemCopyMatching")' 2>/dev/null | tail -30)
COUNT=$(printf '%s\n' "$AU" | rg -c 'AutoUnlock|SecItemCopyMatching' || echo 0)
emit C sharingd_recent "$(python3 -c 'import json,sys; print(json.dumps({"count":int(sys.argv[1]),"tail":sys.argv[2].splitlines()[-8:]}))' "$COUNT" "$AU")"

echo "=== Done. Close lid ~30s, open again, if prompted run this script once more. ==="
