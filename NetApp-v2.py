from flask import Flask, Response, request, session, json
from keycloak import KeycloakOpenID
from functools import wraps
import requests
import json
#NEF SDK
from evolved5g.swagger_client.rest import ApiException
from evolved5g.sdk import LocationSubscriber
import emulator_utils
import datetime
import time
import os
import configparser
with open('config.json', 'r') as jsonfile: CONFIG=json.load(jsonfile)
    
apiRoot = CONFIG['apiRoot']
nefEMU = CONFIG['nefEMU']
selfURL = CONFIG['selfURL']
keycloakURL = CONFIG['keycloakURL']

nefToken = ''
global nefHeaders

# Initiate Flask App
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.emuUsername = CONFIG['emuUsername']
app.emuPassword = CONFIG['emuPassword']
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)

#check emu availability
def check_emus():
    try:
        response = requests.get(apiRoot, verify=False) #SEC removed certificate checking by adding verify=False
        print ("-------dummy API is accessible-------\n")
    except Exception as e:
        print ("-------dummy API not accessible-------\n")
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

#Configure client for KeycloakOpenID
kc_oidc = KeycloakOpenID(server_url=keycloakURL, client_id=CONFIG['keycloakClientID'], realm_name=CONFIG['keycloakRealmName'], client_secret_key=app.secret_key)

#authorization
def require_oauth(f):
    @wraps (f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return Response("User not authenticated.",status=401,mimetype="application/json")
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
    if not "username" in data or not "password" in data:
        return Response("Missing credential info",status=500,mimetype="application/json")
    try: 
        token = kc_oidc.token(data['username'], data['password'])
        session['access_token'] = token
    except Exception as e:
        return Response({'Could not send data to authorization service.'},status=500,mimetype='application/json')
    return token

@app.route('/logout', methods=['GET'])
@require_oauth
def logout():
    try:
        kc_oidc.logout(session['access_token']['refresh_token'])
        session.clear()
    except Exception as e:
        return Response({'Unknown error occurred'},status=500,mimetype='application/json')
    return Response({'Logged out'},status=200,mimetype='application/json')

'''
__________________________
Continuous Authentication |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''
@app.route('/', defaults={'path': ''}, methods=['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'])
@app.route('/<path:path>')
def catch_misuse(path):
    try:
        kc_oidc.logout(session['access_token']['refresh_token'])
        session.clear()
    except Exception as e:
        return Response({'Unknown error occurred'},status=500,mimetype='application/json')
    return Response({'Deauthenticated due to misuse'},status=200,mimetype='application/json')

    
'''
_______________________________
Intermediary Role Fulfillment  |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''

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
    netapp_id = CONFIG['netappId']
    host = emulator_utils.get_host_of_the_nef_emulator()
    token = emulator_utils.get_token()
    location_subscriber = LocationSubscriber(host, token.access_token)
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
    netapp_id = CONFIG['netappId']
    host = emulator_utils.get_host_of_the_nef_emulator()
    token = emulator_utils.get_token()
    location_subscriber = LocationSubscriber(host, token.access_token)
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
    netapp_id = CONFIG['netappId']
    host = emulator_utils.get_host_of_the_nef_emulator()
    token = emulator_utils.get_token()
    location_subscriber = LocationSubscriber(host, token.access_token)
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
    netapp_id = CONFIG['netappId']
    host = emulator_utils.get_host_of_the_nef_emulator()
    token = emulator_utils.get_token()
    location_subscriber = LocationSubscriber(host, token.access_token)
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
    netapp_id = CONFIG['netappId']
    host = emulator_utils.get_host_of_the_nef_emulator()
    token = emulator_utils.get_token()
    location_subscriber = LocationSubscriber(host, token.access_token)
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

'''
________________________
AKMA API                |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''

@app.route('/retrieveKey', methods=['POST'])
@require_oauth
@require_data
def getKey():
    data = request.get_json()
    if not "suppFeat" in data or not "afId" in data or not "aKId" in data:
        return Response("Information incomplete",status=500,mimetype="application/json")
    try: 
        AkmaAfKeyRequest = data
        emuResponse = requests.post(apiRoot+'/3gpp-akma/v1/EMUretrieveKey', json = AkmaAfKeyRequest)
        AkmaAfKeyData = emuResponse.json()
        return AkmaAfKeyData
    except Exception as e:
        return Response({'Could not retrieve AKMA key'},status=500,mimetype='application/json')


'''
________________________
TrafficInfluence API    |
¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
'''

@app.route('/createSubscription', methods=['POST'])
@require_oauth
@require_afId
@require_data
@validate_TrafficInfluSub
def createSub():
    try: 
        TrafficInfluSub = request.get_json()
        NetAppId = request.args.get('afId')
        emuResponse = requests.post(apiRoot+'/3gpp-traffic-influence/v1/'+NetAppId+'/subscriptions', json = TrafficInfluSub)
        res = emuResponse.json()
        return res
    except Exception as e:
        return Response({'Could not create subscription'},status=500,mimetype='application/json')

@app.route('/readSubscriptions', methods=['GET'])
@require_oauth
@require_afId
def readSubs():
    try: 
        NetAppId = request.args.get('afId')
        emuResponse = requests.get(apiRoot+'/3gpp-traffic-influence/v1/'+NetAppId+'/subscriptions')
        res = emuResponse.json()
        return res
    except Exception as e:
        return Response({'Could not read subscriptions'},status=500,mimetype='application/json')

@app.route('/readSubscription', methods=['GET'])
@require_oauth
@require_afId
@require_subId
def readSub():
    try: 
        NetAppId = request.args.get('afId')
        SubscriptionID = request.args.get('subscriptionId')
        emuResponse = requests.get(apiRoot+'/3gpp-traffic-influence/v1/'+NetAppId+'/subscriptions/'+SubscriptionID)
        res = emuResponse.json()
        return res
    except Exception as e:
        return Response({'Could not read subscriptions'},status=500,mimetype='application/json')

@app.route('/modifySubscription', methods=['PUT'])
@require_oauth
@require_afId
@require_subId
@require_data
@validate_TrafficInfluSub
def modifySub():
    try: 
        TrafficInfluSub = request.get_json()
        NetAppId = request.args.get('afId')
        SubscriptionID = request.args.get('subscriptionId')
        emuResponse = requests.put(apiRoot+'/3gpp-traffic-influence/v1/'+NetAppId+'/subscriptions/'+SubscriptionID, json = TrafficInfluSub)
        res = emuResponse.json()
        return res
    except Exception as e:
        return Response({'Could not read subscriptions'},status=500,mimetype='application/json')

@app.route('/editSubscription', methods=['PATCH'])
@require_oauth
@require_afId
@require_subId
@require_data
@validate_TrafficInfluSub
def editSub():
    try: 
        TrafficInfluSub = request.get_json()
        NetAppId = request.args.get('afId')
        SubscriptionID = request.args.get('subscriptionId')
        emuResponse = requests.patch(apiRoot+'/3gpp-traffic-influence/v1/'+NetAppId+'/subscriptions/'+SubscriptionID, json = TrafficInfluSub)
        res = emuResponse.json()
        return res
    except Exception as e:
        return Response({'Could not read subscriptions'},status=500,mimetype='application/json')
    
@app.route('/deleteSubscription', methods=['DELETE'])
@require_oauth
@require_afId
@require_subId
def deleteSub():
    try: 
        NetAppId = request.args.get('afId')
        SubscriptionID = request.args.get('subscriptionId')
        emuResponse = requests.delete(apiRoot+'/3gpp-traffic-influence/v1/'+NetAppId+'/subscriptions/'+SubscriptionID)
        res = emuResponse.json()
        return res
    except Exception as e:
        return Response({'Could not read subscriptions'},status=500,mimetype='application/json')


# Run Flask App
if __name__ == '__main__':

    print(
    """
 ┌───────────────────────────────────────────────────────────┐
 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    IQB NetApp v 2.0   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
 └───────────────────────────────────────────────────────────┘
    \n""")
    check_emus()
    app.run(debug=True, host='0.0.0.0', port=5000) #SEC use waitress-serve for production SEC change debug to false when finalized, add ssl_context
    
    #autoflake --in-place --remove-all-unused-imports "NetApp-v2.py"

