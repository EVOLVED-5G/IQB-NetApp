echo "Waiting for keycloak to fully start..."
while [ "$(curl --location --silent --output /dev/null -w "%{http_code}" --show-error ${KEYCLOAK_ADDRESS}:8080/auth)" != "200" ]; do sleep 1; done
echo "Keycloak has started!"
echo "Obtaining token..."
token=$(curl --silent --data "username=${KEYCLOAK_ADMIN}&password=${KEYCLOAK_ADMIN_PASSWORD}&grant_type=password&client_id=admin-cli" ${KEYCLOAK_ADDRESS}/realms/master/protocol/openid-connect/token)
#echo "$token"
echo "Stripping access token..."
access_token=$(echo $token | sed 's/."access_token":"//g' | sed 's/".*//g')
#echo "$access_token"
echo "Creating user..."
curl --silent ${KEYCLOAK_ADDRESS}/admin/realms/EVOLVED-5G/users -H "Content-Type:  application/json" -H "Authorization: bearer $access_token" --data '{"username": "sampleuser", "credentials":[{"type":"password","value":"test","temporary":false}], "firstName": "testname", "lastName": "testlastname", "email": "test@gmail.com", "enabled": "true"}'
