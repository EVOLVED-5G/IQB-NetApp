
FROM python:3.9

# FROM base_image:version 

# adds a base image that provides a predefined environment-eg OS + specific programs installed 
  

# install dependencies 

WORKDIR /app 

COPY requirements.txt requirements.txt 
RUN pip3 install -r requirements.txt
  

# copy all files and folders of the NetApp Python project into the image 

COPY NetApp-v3.py /app   
COPY emulator_utils.py /app
COPY config.json /app

#execute commands in the container 

CMD [ "python", "NetApp-v3.py", "--config", "container", "--host=0.0.0.0"] 
ENTRYPOINT ["python3", "-u", "NetApp-v3.py"]
  

# For executing the NetApp you iniciate main.py passing 2 parameters: 

#"config" is set as container to use the proper ip/ports since the Netapp is containerized  

#"host" set to 0.0.0.0 to make the app externally visible (outside of the container) 
