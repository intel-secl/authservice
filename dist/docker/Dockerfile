FROM registry.access.redhat.com/ubi7-init:7.6

COPY authservice-*.bin /tmp/authservice.bin
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN env AAS_NOSETUP=true /tmp/authservice.bin && rm /tmp/authservice.bin

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh"]