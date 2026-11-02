FROM owasp/modsecurity-crs:nginx-alpine

# Copy custom configurations
COPY nginx.conf /etc/nginx/templates/conf.d/default.conf.template
COPY modsec/main.conf /etc/modsecurity.d/main.conf
COPY modsec/crs.conf /etc/modsecurity.d/crs.conf
COPY modsec/rules/custom.conf /etc/modsecurity.d/rules/custom.conf
COPY modsec/rules/exclusions.conf /etc/modsecurity.d/rules/exclusions.conf

# Ensure audit log directory exists with correct permissions and append custom rules to setup template
USER root
RUN mkdir -p /var/log/modsec && chown -R nginx:nginx /var/log/modsec && chmod 777 /var/log/modsec && \
    echo "Include /etc/modsecurity.d/main.conf" >> /etc/nginx/templates/modsecurity.d/setup.conf.template && \
    echo "Include /etc/modsecurity.d/rules/exclusions.conf" >> /etc/nginx/templates/modsecurity.d/setup.conf.template && \
    echo "Include /etc/modsecurity.d/rules/custom.conf" >> /etc/nginx/templates/modsecurity.d/setup.conf.template
USER nginx

EXPOSE 80
