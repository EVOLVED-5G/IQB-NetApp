# to a base image, add below required dependencies to install and execute commands  

# base image in the template provides a linux environment with Python 3.10 

# change base image if necessary 

# dependencies of requirements.txt will be installed 

# add/change commands to be executed in the container if necessary 

 

FROM python:3.9

# FROM base_image:version 

# adds a base image that provides a predefined environment-eg OS + specific programs installed 
  
RUN apt-get update && apt-get install -y nano && apt-get install -y jq && apt-get clean


# install dependencies 

WORKDIR /app 

COPY requirements.txt requirements.txt 
RUN pip3 install -r requirements.txt
  

# copy all files and folders of the NetApp Python project into the image 

RUN mkdir -p /app/capif_onboarding
COPY src/NetApp-v3.py /app   
COPY src/emulator_utils.py /app
COPY src/config.json /app
COPY src/capif_registration.json /app

COPY src/keycloak.sh /app
COPY src/keycloak_utils.py /app

#ONBOARD to CAPIF
COPY src/prepare.sh /app
CMD ["sh", "prepare.sh"]


#execute commands in the container 

#CMD [ "python", "NetApp-v3.py", "--config", "container", "--host=0.0.0.0"] 
#ENTRYPOINT ["python3", "-u", "NetApp-v3.py"]
  

# For executing the NetApp you iniciate main.py passing 2 parameters: 

#"config" is set as container to use the proper ip/ports since the Netapp is containerized  

#"host" set to 0.0.0.0 to make the app externally visible (outside of the container) 
