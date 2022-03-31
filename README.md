# Auth Portal

[![Image Size](https://img.shields.io/docker/image-size/glenndehaan/auth-portal)](https://hub.docker.com/r/glenndehaan/auth-portal)

![Auth Portal Login](https://user-images.githubusercontent.com/7496187/146245327-e22daf75-2fe3-4008-a462-9ac7288f6d1b.png)

## What is it?
This auth portal can be seen as a prettified basic auth.
Through the nginx auth module we check if a user is authorized to access an app.
People who are not authorized are redirected to an SSO style login screen, where they can log in with an email address and password.
Users are stored in the Apache Basic Authentication format.

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
    # Optional Volume for JSON users
    #volumes:
    #  - './db:/db'
    # Optional Settings
    #environment:
      #
      # General App Settings
      #
      #APP_TITLE: Auth Portal
      #APP_HEADER: Welcome
      #LOGO: https://upload.wikimedia.org/wikipedia/commons/thumb/9/91/Octicons-mark-github.svg/2048px-Octicons-mark-github.svg.png
      #LOGO_URL: https://github.com
      #BANNER_IMAGE: https://images.unsplash.com/photo-1619976336288-38db38e4c503?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=627&q=80
      #INFO_BANNER: For more info contact the IT team
      #EMAIL_PLACEHOLDER: user@github.com

      #
      # Auth behaviour Settings (Used for loadbalancers like: Traefik, since they forward the redirect)
      #
      #ENABLE_DIRECT_REDIRECT: 'true'
      #AUTH_URL: https://login.example.com/login

      #
      # Cookie Settings
      #
      #COOKIE_DOMAIN: example.com

      #
      # User Settings
      #
      # To create more users run `htpasswd -nm username` then copy the result into here. To specify multiple users add a `\n` after each string
      #USERS: "user@example.com:$apr1$jI2jqzEg$MyNJQxhcZFNygXP79xT/p.\n"
      # If you want to use a JSON file for users enable this option, also make sure the volume is mounted so you can update the JSON on the host machine. This also enables the user activation flow
      #USERS_JSON: 'true'
      # Enables the /admin portal for managing JSON users. Caution: This portal is by default open. We recommend to protect it with for example an IP block.
      #USERS_JSON_ADMIN: 'true'

      #
      # OAuth Provider Settings
      #
      # Google OAuth Config
      #PROVIDER_GOOGLE: 'true'
      #PROVIDER_GOOGLE_CLIENT_ID: xxxxxxxxxx
      #PROVIDER_GOOGLE_CLIENT_SECRET: xxxxxxxxxx
      #PROVIDER_GOOGLE_DOMAIN: example.com

      #
      # JWT (JsonWebToken) Settings
      #
      #JWT_SECRET: xxxxxxxxxx
      #JWT_EXPIRATION: '24h'
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
        proxy_set_header        X-Forwarded-Proto  $scheme;
    }
}
```

* Now add the following snippet to any application you would like to protect with the auth portal:
```
# Any request to this server will first be sent to this URL
auth_request /sso;
auth_request_set $auth_user $upstream_http_x_auth_portal_user;
auth_request_set $auth_resp_err $upstream_http_x_auth_portal_error;

location = /sso {
    proxy_pass http://127.0.0.1:9897/validate;
    proxy_pass_request_body off;

    proxy_set_header Content-Length "";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

error_page 401 = @error401;
location @error401 {
    return 302 https://login.example.com/login?host=$scheme://$http_host&url=$scheme://$http_host$request_uri&error=$auth_resp_err;
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
    auth_request_set $auth_resp_err $upstream_http_x_auth_portal_error;

    location = /sso {
        proxy_pass http://127.0.0.1:9897/validate;
        proxy_pass_request_body off;

        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    error_page 401 = @error401;
    location @error401 {
        return 302 https://login.example.com/login?host=$scheme://$http_host&url=$scheme://$http_host$request_uri&error=$auth_resp_err;
    }
}
```

## App user access
If you would like your app to have access to the currently logged-in users email address
Added the following line to your proxy or cgi process:

### Proxy
```
proxy_set_header Remote-User $auth_user;
```

In express, you are now able to retrieve the user like this:
```javascript
app.get('/', (req, res) => {
    res.send(`Hello, ${req.headers['remote-user']}!`);
});
```

### CGI Process
```
fastcgi_param REMOTE_USER $auth_user;
```

In PHP, you are now able to retrieve the user like this:
```php
<?php
echo 'Hello, ' . $_SERVER['REMOTE_USER'] . '!';
```

## Google OAuth Provider
* Create a project within Google's Cloud portal: https://console.cloud.google.com
* Set up the OAuth consent screen. Next ensure the following scopes are selected:

![Screenshot-20211216092824-798x724](https://user-images.githubusercontent.com/7496187/146335615-c67cddce-1710-4f6f-997a-5b251f9f2f6e.png)

* Create a new OAuth credential and set up the authorized redirects as follows:

![Screenshot-20211216093330-632x769](https://user-images.githubusercontent.com/7496187/146336217-a77069ab-cb42-4e79-8806-cef7e221d75c.png)

## License

MIT
