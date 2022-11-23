In one window:
`docker stop netapp && docker rm netapp && docker build --tag iqb . && docker run --name netapp -p 5000:5000 iqb`

In another window:
`docker exec netapp python -m unittest NetApp-v3`

Running in docker:
`docker-compose up`
Updating client secrets in iqb_netapp container's config.json, creating a user in keycloak are mandatory

(`apt-get update && apt-get install nano` to edit config.json)
