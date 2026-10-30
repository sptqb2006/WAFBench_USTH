FROM owasp/modsecurity-crs:4.0.0-nginx-alpine-202404070701

# Copy custom configurations
COPY nginx.conf /etc/nginx/templates/conf.d/default.conf.template
COPY modsec/main.conf /etc/modsecurity.d/main.conf
COPY modsec/crs.conf /etc/modsecurity.d/crs.conf
COPY modsec/rules/custom.conf /etc/modsecurity.d/rules/custom.conf
COPY modsec/rules/exclusions.conf /etc/modsecurity.d/rules/exclusions.conf

# Ensure audit log directory exists with correct permissions
RUN mkdir -p /var/log/modsec && chmod 777 /var/log/modsec

EXPOSE 80
