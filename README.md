<br />

Setting up the environment:
---
- Run CAPIF services using `sudo ./run.sh` in the CAPIF directory inside the services folder
- Then start the NEF emulator using `make up` in the NEF directory
- Make sure the NetApp is not already registered in the mongodb (http://0.0.0.0:8082/db/capif/user)

In order to start the services:
---
- Execute `docker-compose build && docker-compose up` from this directory. The three containers should start. In order for the NetApp to be functional, the keycloak instance must fully load (1-2 min).


Running Unit Tests:
---
- In another terminal use the command: `docker exec iqb_netapp python -m unittest NetApp-v3`

- Further Testing:
Open Postman and load the collection `Dockerizedv4.postman_collection.json`. 

<br /><br /><br /><br /><br /><br />


<h4>Notes and Debugging</h4>

<h6>In order to test callbacks use the container's name (callbacks:5002) unless the callbacks server is running independently on the host.</h6>

<h6>Checking whether all containers are in the same network:</h6>

```
docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -aq)
```

<h6>Starting the services and configuring the IdP (Keycloak):</h6>

- <h6>From this directory execute `docker-compose build` </h6>
- <h6>Execute `docker-compose up` and wait for keycloak to fully boot (check if it is accessible in URL http://localhost:8980/auth) </h6>
- <h6>In keycloak create a new user with name `sampleuser` and set the toggles `User Enabled` and `Email Verified` to `ON`. </h6>
- <h6>From the credentials tab set the password to `test` and set the toggle `Temporary` to `OFF`. </h6>

<br />

<h6>Importing clients configuration to the NetApp: </h6>

- <h6> For each client (client-netapp, first-provider, second-provider), generate a new secret and add it to the `src\config.json` file. </h6>
- <h6> In order to load the new configuration rebuild the NetApp image only, run it and mount it to the existing network again using the following command in a new Terminal window: </h6>
```
docker stop iqb_netapp \
&& docker rm iqb_netapp \
&& docker build --tag iqb_netapp_img . \
&& docker run --name iqb_netapp --net=services_default -p 5000:5000 iqb_netapp_img
```
_<h6> One-liner: </h6> `docker stop iqb_netapp && docker rm iqb_netapp && docker build --tag iqb_netapp_img . && docker run --name iqb_netapp --net=services_default -p 5000:5000 iqb_netapp_img`_


