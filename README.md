<br />

Setting up the environment:
---
- Run CAPIF services using `sudo ./run.sh` in the CAPIF directory inside the services folder
- Then start the NEF emulator using `make up` in the NEF directory
- Make sure the NetApp is not already registered in the mongodb (http://0.0.0.0:8082/db/capif/user)

<br />

Starting the services and configuring the IdP (Keycloak):
---
- From this directory execute `docker-compose build`
- Execute `docker-compose up` and wait for keycloak to fully boot (check if it is accessible in URL http://localhost:8090/auth)
- In keycloak create a new user with name `sampleuser` and set the toggles `User Enabled` and `Email Verified` to `ON`.
- From the credentials tab set the password to `test` and set the toggle `Temporary` to `OFF`.

<br />

Importing clients configuration to the NetApp:
---

- For each client (client-netapp, first-provider, second-provider), generate a new secret and add it to the `src\config.json` file.
- In order to load the new configuration rebuild the NetApp image only, run it and mount it to the existing network again using the following command in a new Terminal window:
```
docker stop iqb_netapp \
&& docker rm iqb_netapp \
&& docker build --tag iqb_netapp_img . \
&& docker run --name iqb_netapp --net=services_default -p 5000:5000 iqb_netapp_img
```
_One-liner: `docker stop iqb_netapp && docker rm iqb_netapp && docker build --tag iqb_netapp_img . && docker run --name iqb_netapp --net=services_default -p 5000:5000 iqb_netapp_img`_

<br />

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

