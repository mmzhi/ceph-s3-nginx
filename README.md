# Ceph S3 Nginx

Implements proxying of authenticated requests to Ceph S3 API.

Provide Docker deployment.

## Usage

The image assumes config file in the container at: `/etc/nginx/conf.d/*.conf` so use the `-v` option to
mount one from your host.

```
docker run -p 8000:8000 -v /path/to/nginx.vh.default.conf:/etc/nginx/conf.d/nginx.vh.default.conf harrykobe/ceph-s3-nginx
```


Example nginx.conf file:
```nginx
  server {
    listen     8000;

    location / {
      proxy_pass http://your_ceph_rgw_ip;

      access_key your_ceph_access_key;
      secret_key the_secret_associated_with_the_above_access_key;

      proxy_set_header Authorization $s3_auth_token;
      proxy_set_header x-amz-date $s3_date;
    }
  }
```