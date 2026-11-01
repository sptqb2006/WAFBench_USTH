FROM owasp/modsecurity-crs:nginx-alpine

USER root

# Copy custom configurations
COPY nginx.conf /etc/nginx/templates/conf.d/default.conf.template
COPY modsec/main.conf /etc/modsecurity.d/main.conf
COPY modsec/crs.conf /etc/modsecurity.d/crs.conf
COPY modsec/rules/custom.conf /etc/modsecurity.d/rules/custom.conf
COPY modsec/rules/exclusions.conf /etc/modsecurity.d/rules/exclusions.conf

# Include custom configurations in modsecurity-override template
RUN echo "Include /etc/modsecurity.d/main.conf" >> /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template && \
    echo "Include /etc/modsecurity.d/rules/custom.conf" >> /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template && \
    echo "Include /etc/modsecurity.d/rules/exclusions.conf" >> /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template

# Ensure audit log directory exists with correct permissions
RUN mkdir -p /var/log/modsec && chown -R nginx:nginx /var/log/modsec && chmod 777 /var/log/modsec

USER nginx

EXPOSE 80
