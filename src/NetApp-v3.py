from flask import Flask, Response, request, session, json
from keycloak import KeycloakOpenID
from functools import wraps
import requests
import json
import unittest
import warnings
warnings.filterwarnings(action="ignore", message="unclosed", category=ResourceWarning)
#NEF SDK
from evolved5g.swagger_client.rest import ApiException
from evolved5g.sdk import LocationSubscriber
import emulator_utils
import keycloak_utils
import datetime
import time
import os
import configparser
with open('config.json', 'r') as jsonfile: CONFIG=json.load(jsonfile)

nefEMU = emulator_utils.get_url_of_the_nef_emulator()
keycloakURL = keycloak_utils.get_url()
unittests = CONFIG['unittest']

nefToken = ''
global nefHeaders

# Initiate Flask App
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.emuUsername = os.environ['NEF_USER']
app.emuPassword = os.environ['NEF_PASSWORD']
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)

#check emu availability
def check_emus():
    try:
        response = requests.get(nefEMU, verify=False) #SEC removed certificate checking by adding verify=False
        print ("----------EMU is accessible----------\n")
        print ("Logging in...")
        log_in_NEF_Emu()
    except Exception as e:
        print ("---------EMU is not accessible--------\n")

#IQB NetApp Authentication
def log_in_NEF_Emu():
    try: 
        global nefHeaders
        credentials = {'username': app.emuUsername, 'password': app.emuPassword}
        print (credentials, end="\n\n")
        nefResponse = requests.post(nefEMU+'/api/v1/login/access-token', data=credentials)
        token = nefResponse.json()
        nefToken = token
        print("nefToken:")
        print(nefToken, end="\n\n")
        nefHeaders = {"Authorization": token['token_type'] + ' ' + token['access_token']}
        print("nefHeaders:")
        print(nefHeaders, end="\n\n")
        nefResponse = requests.post(nefEMU+'/api/v1/login/test-token', headers=nefHeaders)
        result = nefResponse.json()
        print("The NEF response:")
        print(result, end="\n\n")
    except Exception as e:
        raise e

#Configure clients for KeycloakOpenID
providers = keycloak_utils.get_clients()
#print(providers)
kc_oidc = {}
for i in providers:
    kc_oidc[i] = KeycloakOpenID(server_url=keycloakURL + '/', client_id = i, realm_name = providers[i]['realm'], client_secret_key =  providers[i]['secret'])

'''
__________________________
Unit Tests                |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''

class TestMethod(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        warnings.simplefilter("ignore", ResourceWarning)
    
    def test_login_fail(self):
        resp = self.client.post('/login', json={'username': unittests['login']['username'], 'password':  'wrong', 'provider':  unittests['login']['provider']}, content_type="application/json")
        print("\nLogin fail: ", resp.data.decode("utf-8"))
        self.assertEqual("Invalid credentials.", resp.data.decode("utf-8"))
    
    def test_login_fail_provider(self):
        resp = self.client.post('/login', json={'username':  unittests['login']['username'], 'password':   unittests['login']['password'], 'provider': 'wrong'}, content_type="application/json")
        print("\nLogin fail due to provider: ", resp.data.decode("utf-8"))
        self.assertEqual("Invalid information.", resp.data.decode("utf-8"))
    
    def test_login_success(self):
        resp = self.client.post('/login', json=unittests['login'], content_type="application/json")
        print("\nLogin success: ", resp.data.decode("utf-8")[0:100] + '...')
        self.assertTrue("access_token" in resp.data.decode("utf-8"))
    
    def test_unauthorized_access(self):
        resp = self.client.get('/logout')
        print("\nUnauthorized access: ", resp.data.decode("utf-8"))
        self.assertEqual("User not authenticated.", resp.data.decode("utf-8"))
    
    def test_authorized_access(self):
        with app.test_request_context():
            resp = self.client.post('/login', json=unittests['login'], content_type="application/json")
            resp = self.client.get('/logout')
            print("\nAuthorized access: ", resp.data.decode("utf-8"))
            self.assertEqual("Logged out", resp.data.decode("utf-8"))
    
    def test_monitoring_api(self):
        with app.test_request_context():
            resp = self.client.post('/login', json=unittests['login'], content_type="application/json")
            resp = self.client.get('/api/v1/3gpp-monitoring-event/v1/123/subscriptions?skip=0&limit=100', json=json.loads('{}'), content_type="application/json")
            print("\nGet subscriptions: ", resp.data.decode("utf-8"))
            self.assertEqual("[]", resp.data.decode("utf-8"))
    
    def test_continuous_authentication_loggedout(self):
        with app.test_request_context():
            resp = self.client.patch('/api/v1/3gpp-monitoring-event/v1/123/subscriptions?skip=0&limit=100')
            print("\nMisuse (logged out): ", resp.data.decode("utf-8"))
            self.assertEqual("De-authenticated due to misuse", resp.data.decode("utf-8"))

    def test_continuous_authentication_loggedin(self):
        with app.test_request_context():
            resp = self.client.post('/login', json=unittests['login'], content_type="application/json")
            resp = self.client.patch('/api/v1/3gpp-monitoring-event/v1/123/subscriptions?skip=0&limit=100')
            print("\nMisuse (logged in): ", resp.data.decode("utf-8"))
            resp = self.client.get('/logout')
            print("User forcefully logged out: ", resp.data.decode("utf-8"))
            self.assertEqual("User not authenticated.", resp.data.decode("utf-8"))


'''
__________________________
Wrappers                  |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''

#authorization
def require_oauth(f):
    @wraps (f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return Response("User not authenticated.",status=401,mimetype="application/json")
        if kc_oidc[session['provider']].introspect(session['access_token']['access_token'])["active"] != True:
            return Response("User token not active.",status=401,mimetype="application/json")
        return f(*args, **kwargs)
    return decorated_function

#input checks
def require_data(f):
    @wraps (f)
    def decorated_function(*args, **kwargs):
        data=None
        try:
            data = request.get_json()
        except Exception:
            return Response("Bad form content",status=500,mimetype='application/json')
        if data == None:
            return Response("Bad request",status=500,mimetype='application/json')
        return f(*args, **kwargs)
    return decorated_function

def require_afId(f):
    @wraps (f)
    def decorated_function(*args, **kwargs):
        if request.args.get('afId') == None:
            return Response("Information incomplete. Missing NetApp identifier",status=500,mimetype="application/json")
        return f(*args, **kwargs)
    return decorated_function

def require_subId(f):
    @wraps (f)
    def decorated_function(*args, **kwargs):
        if request.args.get('subscriptionId') == None:
            return Response("Information incomplete. Missing NetApp identifier",status=500,mimetype="application/json")
        return f(*args, **kwargs)
    return decorated_function

def validate_TrafficInfluSub(f):
    @wraps (f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        #note 1 for TrafficInfluSub NorthboundAPIs_NEF
        if not "afAppId" in data and not "trafficFilters" in data and not "ethTrafficFilters" in data:
            return Response("Information incomplete (note 1)",status=500,mimetype="application/json") 
        #note 2 for TrafficInfluSub NorthboundAPIs_NEF
        elif not "gpsi" in data and not "ipv4Addr" in data and not "ipv6Addr" in data:
            return Response("Information incomplete  (note 2)",status=500,mimetype="application/json") 
        return f(*args, **kwargs)
    return decorated_function


'''
__________________________
3rd Party Authentication  |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''

@app.route('/login', methods=['POST'])
@require_data
def login():
    data = request.get_json()
    if not "username" in data or not "password" or not "provider" in data:
        return Response("Missing credential info",status=500,mimetype="application/json")
    try: 
        token = kc_oidc[data['provider']].token(data['username'], data['password'])
        session['access_token'] = token
        session['provider'] = data['provider']
    except Exception as e:
        if "Invalid user credentials" in str(e):
            return Response({'Invalid credentials.'},status=401,mimetype='application/json')
        elif "Invalid client secret" in str(e):
            return Response({'Invalid client secret (check config).'},status=401,mimetype='application/json')
        else: 
            return Response({'Invalid information.'},status=401,mimetype='application/json')
    return token

@app.route('/logout', methods=['GET'])
@require_oauth
def logout():
    try:
        kc_oidc[session['provider']].logout(session['access_token']['refresh_token'])
        session.clear()
    except Exception as e:
        return Response({'Unknown error occurred'},status=500,mimetype='application/json')
    return Response({'Logged out'},status=200,mimetype='application/json')


'''
__________________________
Continuous Authentication |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''

@app.errorhandler(405)
def method_not_allowed(e):
    try:
        kc_oidc[session['provider']].logout(session['access_token']['refresh_token'])
        session.clear()
    except Exception as e:
        pass
    return Response({'De-authenticated due to misuse'},status=403,mimetype='application/json')

@app.route('/', defaults={'path': ''}, methods=['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'])
@app.route('/<path:path>')
def catch_misuse(path):
    try:
        kc_oidc[session['provider']].logout(session['access_token']['refresh_token'])
        session.clear()
    except Exception as e:
        pass
    return Response({'De-authenticated due to misuse'},status=403,mimetype='application/json')

    
'''
_______________________________
Intermediary Role Fulfillment  |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''
#TODO when calling a provider's endpoint authenticate against UE's provider (in session variable)

@app.route('/api/v1/3gpp-monitoring-event/v<version>/<scsAsId>/subscriptions', defaults={'subscriptionId': None}, methods=['GET', 'POST'])
@app.route('/api/v1/3gpp-monitoring-event/v<version>/<scsAsId>/subscriptions/<subscriptionId>', methods=['GET', 'PUT', 'DELETE'])
@require_oauth
def monitoring(version, scsAsId, subscriptionId):
    data = request.get_json()
    if request.method == 'GET':
        '''
            try: 
                nefResponse = requests.get(nefEMU+'/api/v1/3gpp-monitoring-event/v'+version+'/'+scsAsId+'/subscriptions', json = data, params = request.args, headers=nefHeaders)
                if nefResponse.status_code == 204:
                    return Response({''},status=204,mimetype='application/json')
                else:
                    return nefResponse.json()
            except Exception as e:
                raise e
            '''
        if subscriptionId == None:
            result = location_read_all_subscriptions()
        else:
            result = location_read_subscription(subscriptionId)
        return Response({str(result)},status=200,mimetype='application/json')
    elif request.method == 'POST':
        status, result = location_create_subscription(data)
        return Response({str(result)},status=200,mimetype='application/json')
    elif request.method == 'DELETE':
        status, result = location_delete_subscription(subscriptionId)
        return Response({str(result)},status=200,mimetype='application/json')
    elif request.method == 'PUT':
        status, result = location_update_subscription(data, subscriptionId)
        return Response({str(result)},status=200,mimetype='application/json')
    else:
        return Response({'Bad Request'},status=500,mimetype='application/json')
@app.route('/api/v1/3gpp-as-session-with-qos/v<version>/<scsAsId>/subscriptions', defaults={'subscriptionId': None}, methods=['GET', 'POST'])
@app.route('/api/v1/3gpp-as-session-with-qos/v<version>/<scsAsId>/subscriptions/<subscriptionId>', methods=['GET', 'PUT', 'DELETE'])
def qos(version, scsAsId, subscriptionId):
    data = request.get_json()
    if request.method == 'GET':
        try: 
            nefResponse = requests.get(nefEMU+'/api/v1/3gpp-monitoring-event/v'+version+'/'+scsAsId+'/subscriptions', json = data, params = request.args, headers=nefHeaders)
            if nefResponse.status_code == 204:
                return Response({''},status=204,mimetype='application/json')
            else:
                return nefResponse.json()
        except Exception as e:
            raise e

'''
________________________
NEF SDK Functionality   |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''

def location_read_all_subscriptions():
    netapp_id = os.environ['NETAPP_ID']
    # host = emulator_utils.get_url_of_the_nef_emulator()
    # token = emulator_utils.get_token_for_nef_emulator()
    location_subscriber = LocationSubscriber(
                                                nef_url= emulator_utils.get_url_of_the_nef_emulator(),
                                                nef_bearer_access_token= emulator_utils.get_token_for_nef_emulator().access_token,
                                                folder_path_for_certificates_and_capif_api_key= emulator_utils.get_folder_path_for_certificated_and_capif_api_key(),
                                                capif_host= emulator_utils.get_capif_host(),
                                                capif_https_port= emulator_utils.get_capif_https_port() 
                                             )

    # location_subscriber = LocationSubscriber(host, token.access_token)
    try:
        all_subscriptions = location_subscriber.get_all_subscriptions(netapp_id, 0, 100) #skip, limit
        print('\n', all_subscriptions, '\n')
        return all_subscriptions
    except ApiException as ex:
        if ex.status == 404:
            print("No active transcriptions found")
            return "No active transcriptions found"
        else: #something else happened, re-throw the exception
            raise

def location_create_subscription(data):
    expire_time = (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat() + "Z"
    netapp_id = os.environ['NETAPP_ID']
    location_subscriber = LocationSubscriber(
                                                nef_url= emulator_utils.get_url_of_the_nef_emulator(),
                                                nef_bearer_access_token= emulator_utils.get_token_for_nef_emulator().access_token,
                                                folder_path_for_certificates_and_capif_api_key= emulator_utils.get_folder_path_for_certificated_and_capif_api_key(),
                                                capif_host= emulator_utils.get_capif_host(),
                                                capif_https_port= emulator_utils.get_capif_https_port() 
                                             )
    try:
        subscription = location_subscriber.create_subscription(
            netapp_id=netapp_id,
            external_id=data["externalId"],
            notification_destination=data["notificationDestination"],
            maximum_number_of_reports=data["maximumNumberOfReports"],
            monitor_expire_time=data["monitorExpireTime"]
        )
        print(subscription)
        return True, subscription
    except ApiException as ex:
        if ex.status == 409:
            print("\nThere is already an active subscription for UE with external id", data["externalId"], '\n')
            return False, "There is already an active subscription for UE with external id " + data["externalId"]
        else: #something else happened, re-throw the exception
            raise

def location_read_subscription(subscription_id):
    netapp_id = os.environ['NETAPP_ID']
    location_subscriber = LocationSubscriber(
                                                nef_url= emulator_utils.get_url_of_the_nef_emulator(),
                                                nef_bearer_access_token= emulator_utils.get_token_for_nef_emulator().access_token,
                                                folder_path_for_certificates_and_capif_api_key= emulator_utils.get_folder_path_for_certificated_and_capif_api_key(),
                                                capif_host= emulator_utils.get_capif_host(),
                                                capif_https_port= emulator_utils.get_capif_https_port() 
                                             )
    try:
        subscription = location_subscriber.get_subscription(netapp_id, subscription_id)
        print('\n', subscription, '\n')
        return subscription
    except ApiException as ex:
        if ex.status == 404:
            print("No active transcriptions found")
            return "No active transcriptions found"
        else: #something else happened, re-throw the exception
            raise

def location_delete_subscription(subscription_id):
    netapp_id = os.environ['NETAPP_ID']
    location_subscriber = LocationSubscriber(
                                                nef_url= emulator_utils.get_url_of_the_nef_emulator(),
                                                nef_bearer_access_token= emulator_utils.get_token_for_nef_emulator().access_token,
                                                folder_path_for_certificates_and_capif_api_key= emulator_utils.get_folder_path_for_certificated_and_capif_api_key(),
                                                capif_host= emulator_utils.get_capif_host(),
                                                capif_https_port= emulator_utils.get_capif_https_port() 
                                             )
    try: 
        subscription = location_subscriber.delete_subscription(netapp_id, subscription_id)
        print("Deleted subscription with id: " + subscription_id)
        return True, subscription
    except ApiException as ex:
        if ex.status == 404:
            print("No active transcriptions found")
            return False, "No active transcriptions found"
        else: #something else happened, re-throw the exception
            raise
            
def location_update_subscription(data, subscription_id):
    netapp_id = os.environ['NETAPP_ID']
    location_subscriber = LocationSubscriber(
                                                nef_url= emulator_utils.get_url_of_the_nef_emulator(),
                                                nef_bearer_access_token= emulator_utils.get_token_for_nef_emulator().access_token,
                                                folder_path_for_certificates_and_capif_api_key= emulator_utils.get_folder_path_for_certificated_and_capif_api_key(),
                                                capif_host= emulator_utils.get_capif_host(),
                                                capif_https_port= emulator_utils.get_capif_https_port() 
                                             )
    try:
        subscription = location_subscriber.update_subscription(
            netapp_id=netapp_id,
            subscription_id=subscription_id,
            external_id=data["externalId"],
            notification_destination=data["notificationDestination"],
            maximum_number_of_reports=data["maximumNumberOfReports"],
            monitor_expire_time=data["monitorExpireTime"]
        )
        print(subscription)
        return True, subscription
    except ApiException as ex:
        if ex.status == 409:
            print("\nUpdating subscription failed", data["externalId"], '\n')
            return False, "Updating subscription failed"
        else: #something else happened, re-throw the exception
            raise

#Duplicate monitoring API for validation pipeline
def monitor_subscription(data):
    expire_time = (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat() + "Z"
    netapp_id = os.environ['NETAPP_ID']
    location_subscriber = LocationSubscriber(
                                                nef_url= emulator_utils.get_url_of_the_nef_emulator(),
                                                nef_bearer_access_token= emulator_utils.get_token_for_nef_emulator().access_token,
                                                folder_path_for_certificates_and_capif_api_key= emulator_utils.get_folder_path_for_certificated_and_capif_api_key(),
                                                capif_host= emulator_utils.get_capif_host(),
                                                capif_https_port= emulator_utils.get_capif_https_port() 
                                             )
    try:
        subscription = location_subscriber.create_subscription(
            netapp_id=netapp_id,
            external_id=data["externalId"],
            notification_destination=data["notificationDestination"],
            maximum_number_of_reports=data["maximumNumberOfReports"],
            monitor_expire_time=data["monitorExpireTime"]
        )
        monitoring_response = subscription.to_dict()
        
        return monitoring_response
    except ApiException as ex:
        if ex.status == 409:
            print("\nThere is already an active subscription for UE with external id", data["externalId"], '\n')
            return False, "There is already an active subscription for UE with external id " + data["externalId"]
        else: #something else happened, re-throw the exception
            raise

# Run Flask App
if __name__ == '__main__':

    print(
    """
 ┌───────────────────────────────────────────────────────────┐
 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    IQB NetApp v 2.4  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
 └───────────────────────────────────────────────────────────┘
    \n""")
    check_emus()
    app.run(debug=True, host='0.0.0.0', port=5000) #SEC use waitress-serve for production SEC change debug to false when finalized, add ssl_context
    
    #autoflake --in-place --remove-all-unused-imports "NetApp-v2.py"

