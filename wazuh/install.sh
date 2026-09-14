#!/bin/sh
# Install the OpenCTI middleware integration on a Wazuh manager.
#
#   sudo ./install.sh [/var/ossec]
#
# Copies the integration and rules into place with the ownership and modes
# Wazuh requires, then tells you what to add to ossec.conf. It deliberately
# does not edit ossec.conf itself.
set -eu

OSSEC="${1:-/var/ossec}"
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$OSSEC" ]; then
    echo "error: $OSSEC not found. Pass the Wazuh path as the first argument." >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root (the files must be owned by root:wazuh)." >&2
    exit 1
fi

echo "Installing into $OSSEC"

# Wazuh requires the integration to be root:wazuh 750. analysisd runs as
# wazuh and needs execute; nothing else should be able to read the API key
# out of the process table or edit the script.
for f in custom-opencti custom-opencti.py; do
    install -o root -g wazuh -m 750 "$SRC/$f" "$OSSEC/integrations/$f"
    echo "  integrations/$f"
done

install -o wazuh -g wazuh -m 660 \
    "$SRC/0910-opencti_rules.xml" "$OSSEC/etc/rules/0910-opencti_rules.xml"
echo "  etc/rules/0910-opencti_rules.xml"

cat <<'EOF'

Next:

  1. Add this to <ossec_config> in etc/ossec.conf, with your own values:

       <integration>
         <name>custom-opencti</name>
         <hook_url>http://opencti-middleware:8000</hook_url>
         <api_key>YOUR_MIDDLEWARE_API_KEY</api_key>
         <alert_format>json</alert_format>
         <group>sysmon_event3,sysmon_event1,sysmon_event_22,syscheck</group>
       </integration>

     Scope <group> or <level> tightly. The integration runs as a separate
     process per matching alert, so the filter is what decides your load.

  2. Restart:   systemctl restart wazuh-manager

  3. Verify:    tail -f /var/ossec/logs/integrations.log

To test without waiting for a real alert:

  /var/ossec/integrations/custom-opencti /tmp/alert.json <api_key> <hook_url> debug

where /tmp/alert.json holds a single alert, e.g.

  {"id":"1","agent":{"id":"001","name":"h","ip":"10.0.0.1"},
   "rule":{"id":"92000","description":"test","groups":["sysmon_event3"]},
   "data":{"eventdata":{"DestinationIp":"1.2.3.4"}}}
EOF
