from evolved5g import swagger_client
from evolved5g.swagger_client import LoginApi, ApiClient, User, Configuration
from evolved5g.swagger_client.models import Token
from evolved5g.sdk import LocationSubscriber
import json
import configparser
import os
with open('config.json', 'r') as jsonfile: CONFIG=json.load(jsonfile)

def get_location_subscriber() -> LocationSubscriber:
    location_subscriber = LocationSubscriber(
                                                nef_url= get_url_of_the_nef_emulator(),
                                                nef_bearer_access_token= get_nef_token().access_token,
                                                folder_path_for_certificates_and_capif_api_key= get_certificates_folder(),
                                                capif_host= get_capif_host(),
                                                capif_https_port= get_capif_https_port() 
                                            )
    return location_subscriber


def get_nef_token() -> Token:
    username = os.environ['NEF_USER']
    password = os.environ['NEF_PASSWORD']
    configuration = Configuration()
    configuration.host = get_url_of_the_nef_emulator()
    configuration.verify_ssl = False
    api_client = ApiClient(configuration=configuration)
    api_client.select_header_content_type(["application/x-www-form-urlencoded"])
    api = LoginApi(api_client)
    token = api.login_access_token_api_v1_login_access_token_post("", username, password, "", "", "")

    return token


def get_api_client(token) -> swagger_client.ApiClient:
    configuration = swagger_client.Configuration()
    configuration.host = get_url_of_the_nef_emulator()
    configuration.access_token = token.access_token
    api_client = swagger_client.ApiClient(configuration=configuration)
    return api_client


def get_url_of_the_nef_emulator() -> str:
    return "https://" + os.environ['NEF_ADDRESS']

def get_certificates_folder()->str:
    """
    This is the folder that was provided when you registered the NetApp to CAPIF.
    It contains the certificates and the api.key needed to communicate with the CAPIF server
    :return:
    """
    return os.environ['PATH_TO_CERTS']
    #return "/app/capif_onboarding"

def get_capif_host()->str:
    """
    When running CAPIF via docker (by running ./run.sh) you should have at your /etc/hosts the following record
    127.0.0.1       capifcore
    :return:
    """
    return os.environ['CAPIF_HOSTNAME']
    #return "capifcore"

def get_capif_https_port()->int:
    """
    This is the default https port when running CAPIF via docker
    :return:
    """
    return os.environ['CAPIF_PORT_HTTPS']
    #return 443
