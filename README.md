# Auth Portal Example

[![Image Size](https://img.shields.io/docker/image-size/glenndehaan/auth-portal)](https://hub.docker.com/r/glenndehaan/auth-portal)

## Development Usage
Make sure you have Node.JS 14.x installed then run the following commands in your terminal:
```
./app-install-dependencies.sh
./app-run.sh
```

## Run the auth portal in production
The Auth portal is available for your own applications.
Follow the guide below to install the portal onto your server:

* Create a docker-compose.yml file with the following contents:
```yaml
version: '2'
services:
  auth:
    image: glenndehaan/auth-portal
    ports:
      - '9897:3000'
    # Optional Settings
    #environment:
      #APP_TITLE: Auth Portal
      #APP_HEADER: Welcome
      #LOGO: https://upload.wikimedia.org/wikipedia/commons/thumb/9/91/Octicons-mark-github.svg/2048px-Octicons-mark-github.svg.png
      #LOGO_URL: https://github.com
      #EMAIL_PLACEHOLDER: user@github.com
      # To create more users run `htpasswd -nm username` then copy the result into here. To specify multiple users add a `\n` after each string
      #USERS: "user@example.com:$apr1$jI2jqzEg$MyNJQxhcZFNygXP79xT/p.\n"
```

* Run `docker-compose up -d` this pulls the auth portal and starts it headless
* Create a nginx host file to proxy the auth portal, example:
```
server {
    listen 80;

    server_name login.example.com;

    access_log /var/log/nginx/access_login.example.com.log;
    error_log /var/log/nginx/error_login.example.com.log;

    location / {
        proxy_pass http://127.0.0.1:9897;
        proxy_http_version      1.1;
        proxy_set_header        Host               $host;
        proxy_set_header        X-Real-IP          $remote_addr;
        proxy_set_header        X-Forwarded-For    $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Host   $host;
        proxy_set_header        X-Forwarded-Server $host;
    }
}
```

* Now add the following snippet to any application you would like to protect with the auth portal:
```
# Any request to this server will first be sent to this URL
auth_request /sso;
auth_request_set $auth_user $upstream_http_x_auth_portal_user;
auth_request_set $auth_resp_jwt $upstream_http_x_auth_portal_jwt;
auth_request_set $auth_resp_err $upstream_http_x_auth_portal_error;

location = /sso {
    proxy_pass http://127.0.0.1:9897/validate;
    proxy_pass_request_body off;

    proxy_set_header Content-Length "";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location = /sso/redirect {
    auth_request off;

    add_header Set-Cookie "__auth_portal=$arg_jwt;Path=/;";
    return 302 $arg_redirect;
}

error_page 401 = @error401;
location @error401 {
    return 302 https://login.example.com/login?host=$scheme://$http_host&url=$scheme://$http_host$request_uri&jwt=$auth_resp_jwt&error=$auth_resp_err;
}
```

## Example secure application
Below you will find a complete nginx host file for the `secure.example.com` app:
```
server {
    listen 80;

    server_name secure.example.com;
    root /var/www;

    access_log /var/log/nginx/access_secure.example.com.log;
    error_log /var/log/nginx/error_secure.example.com.log;

    # Any request to this server will first be sent to this URL
    auth_request /sso;
    auth_request_set $auth_user $upstream_http_x_auth_portal_user;
    auth_request_set $auth_resp_jwt $upstream_http_x_auth_portal_jwt;
    auth_request_set $auth_resp_err $upstream_http_x_auth_portal_error;

    location = /sso {
        proxy_pass http://127.0.0.1:9897/validate;
        proxy_pass_request_body off;

        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /sso/redirect {
        auth_request off;

        add_header Set-Cookie "__auth_portal=$arg_jwt;Path=/;";
        return 302 $arg_redirect;
    }

    error_page 401 = @error401;
    location @error401 {
        return 302 https://login.example.com/login?host=$scheme://$http_host&url=$scheme://$http_host$request_uri&jwt=$auth_resp_jwt&error=$auth_resp_err;
    }
}
```
