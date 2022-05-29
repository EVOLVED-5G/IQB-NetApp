FROM nginx
COPY ./src /usr/share/nginx/html
# support running as arbitrary user which belogs to the root group
RUN chmod g+rwx /var/cache/nginx /var/run /var/log/nginx
# users are not allowed to listen on priviliged ports
RUN sed -i.bak 's/listen\(.*\)80;/listen 5000;/' /etc/nginx/conf.d/default.conf
EXPOSE 5000
# comment user directive as master process is run as user in OpenShift anyhow
RUN sed -i.bak 's/^user/#user/' /etc/nginx/nginx.conf

#Dockerfile START
FROM python:3.9
WORKDIR /app 

COPY requirements.txt requirements.txt 

RUN pip3 install -r requirements.txt 

  

# copy all files and folders of the NetApp Python project into the image 

COPY NetApp-v2.py /app   
COPY emulator_utils.py /app
COPY config.json /app

#execute commands in the container 

CMD [ "python", "NetApp-v2.py", "--config", "container", "--host=0.0.0.0"] 
ENTRYPOINT ["python3", "-u", "NetApp-v2.py"]