FROM build-keripy

WORKDIR /verifier
COPY ./ ./

RUN pip install -r requirements.txt

RUN mkdir -p /usr/local/var/keri

ENTRYPOINT ["verifier", "server", "start", "--config-dir", "scripts", "--config-file", "verifier-config.json"]
