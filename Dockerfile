FROM certbot/certbot
COPY ./dist/certbot_dns_onedotcom-1.0.0-py3-none-any.whl /tmp/
RUN pip install /tmp/certbot_dns_onedotcom-1.0.0-py3-none-any.whl && pip install beautifulsoup4 && rm /tmp/*

ENTRYPOINT [ "/bin/sh" ]