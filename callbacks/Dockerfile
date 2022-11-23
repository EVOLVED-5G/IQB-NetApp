# to a base image, add below required dependencies to install and execute commands  

# base image in the template provides a linux environment with Python 3.10 

# change base image if necessary 

# dependencies of requirements.txt will be installed 

# add/change commands to be executed in the container if necessary 

 

FROM python:3.9

# FROM base_image:version 

# adds a base image that provides a predefined environment-eg OS + specific programs installed 
  

# install dependencies 

WORKDIR /app 

COPY requirements.txt requirements.txt 
RUN pip3 install -r requirements.txt
  

# copy all files and folders of the NetApp Python project into the image 

COPY /callbacks.py /app  

#execute commands in the container 

CMD [ "python", "callbacks.py", "--config", "container", "--host=0.0.0.0"] 
ENTRYPOINT ["python3", "-u", "callbacks.py"]
  

# For executing the NetApp you iniciate main.py passing 2 parameters: 

#"config" is set as container to use the proper ip/ports since the Netapp is containerized  

#"host" set to 0.0.0.0 to make the app externally visible (outside of the container) 