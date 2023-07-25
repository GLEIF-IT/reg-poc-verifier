FROM build-keripy

WORKDIR /verifier
RUN git clone https://github.com/GLEIF-IT/reg-poc-verifier.git .
RUN git checkout cc223329d48eede7a41730de01b30d3fce3a1f1f

RUN pip install -r requirements.txt

WORKDIR /keripy
RUN mkdir -p /usr/local/var/keri
RUN pip install -e .

WORKDIR /verifier
RUN mkdir -p /verifier/scripts/keri/cf/

COPY ./config/verifier/verifier-config.json /verifier/scripts/keri/cf/verifier-config.json

ENTRYPOINT ["verifier", "server", "start", "--config-dir", "scripts", "--config-file", "verifier-config.json"]
