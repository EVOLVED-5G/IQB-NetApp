In one window:
`docker stop netapp && docker rm netapp && docker build --tag iqb . && docker run --name netapp -p 5000:5000 iqb`

In another window:
`docker exec netapp python -m unittest NetApp-v3`

