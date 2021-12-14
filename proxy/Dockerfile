#
# Define OS
#
FROM alpine:3.14

#
# Basic OS management
#

# Install packages
RUN apk add --no-cache nginx

#
# Setup app
#

# Copy nginx config
COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./default.conf /etc/nginx/conf.d/default.conf

# Forward request and error logs to docker log collector
RUN ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log

# Expose nginx
EXPOSE 3001

# Check for nginx stopcode
STOPSIGNAL SIGTERM

# Run nginx
CMD ["nginx", "-g", "daemon off;"]
