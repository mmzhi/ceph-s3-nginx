# Ceph S3 Nginx

Implements proxying of authenticated requests to Ceph S3 API.

Provide Docker deployment.

## Usage

The image assumes config file in the container at: `/etc/nginx/conf.d/*.conf` so use the `-v` option to
mount one from your host.

```
docker build -t ceph-s3-nginx .
docker run -p 8000:8000 -v /path/to/nginx.vh.default.conf:/etc/nginx/conf.d/nginx.vh.default.conf ceph-s3-nginx
```
