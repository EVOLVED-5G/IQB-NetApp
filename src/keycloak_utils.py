import requests
import os
import json
import configparser
import time
with open('config.json', 'r') as jsonfile: CONFIG=json.load(jsonfile)

def get_url() -> str:
	keycloakURL = "http://" + os.environ['KEYCLOAK_ADDRESS']
	return keycloakURL

def get_realm() -> str:
	realm = os.environ['KEYCLOAK_REALM']
	return realm

def get_admin_token() -> dict:
	url = get_url()
	data = {"username": os.environ['KEYCLOAK_ADMIN'], "password": os.environ['KEYCLOAK_ADMIN_PASSWORD'], "grant_type": "password", "client_id": "admin-cli" }
	token = requests.post(url + "/realms/master/protocol/openid-connect/token", data=data).text
	return json.loads(token)
	
def get_admin_token_string() -> str:
	token = get_admin_token()
	access_token = token['access_token']
	return access_token

def get_info_of_clients() -> dict:
	url = get_url()
	realm = get_realm()
	access_token = get_admin_token_string()
	clients = requests.get(url + "/admin/realms/" + realm + "/clients", headers={"Authorization": "bearer " + access_token}).text
	clientsdict = json.loads(clients)
	return clientsdict #thiis has dicts in it

def get_providers_from_config () -> dict:
	configproviders = CONFIG['providers']
	providers = {}
	for i in configproviders:
		providers[i] = {"realm": configproviders[i], "id": None, "secret": None}
	return providers #this does not have dicts in it smh

def get_ids_of_clients() -> dict:
	providers = get_providers_from_config()
	clients = get_info_of_clients()
	for client in clients:
                if client['clientId'] in providers:
                	providers[client['clientId']]['id'] = client['id']
	return providers

def get_secrets_of_clients() -> dict:
	url = get_url()
	realm = get_realm()
	access_token = get_admin_token_string()
	clients = get_ids_of_clients()
	data = {"username": os.environ['KEYCLOAK_ADMIN'], "password": os.environ['KEYCLOAK_ADMIN_PASSWORD'], "grant_type": "password", "client_id": "admin-cli" }
	for i in clients: 
		client = clients[i] #need the value of every client key
		secret = requests.get(url + "/admin/realms/" + realm + "/clients/" + client['id'] + "/client-secret", data=data, headers={"Authorization": "bearer " + access_token}).text
		secret = json.loads(secret)
		client['secret'] = secret['value']
	return clients

def get_clients() -> dict:
	#time.sleep(300)
	return get_secrets_of_clients()
		
#curl ${KEYCLOAK_ADDRESS}/admin/realms/" + realm + "/clients -H "Authorization: bearer $access_token" 
#response = requests.get("https://" + os.environ['KEYCLOAK_ADDRESS'] + "/admin/realms/" + realm + "-5G/clients/{myclientid}/client-secret", data=data, headers= {"Authorization": "Bearer " + token.get('access_token'), "Content-Type": "application/json"})

