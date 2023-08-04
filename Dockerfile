ARG BASE_IMAGE=keripy
FROM ${BASE_IMAGE}


WORKDIR /verifier
COPY ./ ./

RUN pip install -r requirements.txt \
    && mkdir -p /verifier/scripts/keri/cf/

ENTRYPOINT ["verifier", "server", "start", "--config-dir", "scripts", "--config-file", "verifier-config.json"]
