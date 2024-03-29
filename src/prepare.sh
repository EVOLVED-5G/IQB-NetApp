jq -r .capif_host=\"$CAPIF_HOSTNAME\" capif_registration.json >> tmp.json && mv tmp.json capif_registration.json
jq -r .capif_http_port=\"$CAPIF_PORT_HTTP\" capif_registration.json >> tmp.json && mv tmp.json capif_registration.json
jq -r .capif_https_port=\"$CAPIF_PORT_HTTPS\" capif_registration.json >> tmp.json && mv tmp.json capif_registration.json
jq -r .capif_callback_url=\"http://$CALLBACK_ADDRESS\" capif_registration.json >> tmp.json && mv tmp.json capif_registration.json
evolved5g register-and-onboard-to-capif --config_file_full_path="/app/capif_registration.json" --environment="$ENVIRONMENT_MODE"
sh ./keycloak.sh 
python3 -u NetApp-v3.py
