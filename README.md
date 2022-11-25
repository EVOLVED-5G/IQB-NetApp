Re-building the netapp in docker: 

In one window:
`docker stop iqb_netapp && docker rm iqb_netapp && docker build --tag iqb_netapp_img . && docker run --name iqb_netapp --net=services_default -p 5000:5000 iqb_netapp_img`

---

Running in docker:
`docker-compose up`
Updating client secrets in iqb_netapp container's config.json, creating a user in keycloak are mandatory

---

Running unit tests:

In another window:
`docker exec iqb_netapp python -m unittest NetApp-v3`

---

In order to test callbacks use the host's IP and port of the callbacks server in case NEF is running in a VM in the host or the container's name (callbacks:5002)

---

Checking whether all containers are in the same network:
`docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -aq)`
