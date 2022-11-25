Re-building the netapp in docker: 

In one window:
`docker stop netapp && docker rm netapp && docker build --tag iqb . && docker run --name netapp -p 5000:5000 iqb`

In another window:
`docker exec netapp python -m unittest NetApp-v3`


---

Running in docker:
`docker-compose up`
Updating client secrets in iqb_netapp container's config.json, creating a user in keycloak are mandatory

(`apt-get update && apt-get install nano` to edit config.json)

---

Running unit tests:

In another window:
`docker exec iqb_netapp python -m unittest NetApp-v3`

---

In order to test callbacks use the host's IP and port of the callbacks server in case NEF is running in a VM in the host or the container's name (callbacks:5002)

---

Checking whether all containers are in the same network:
`docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -aq)`
