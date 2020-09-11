FROM centos:8

RUN useradd -u 1001 --comment "Authservice" --home /opt/authservice  --shell /bin/false aas

RUN mkdir -p /opt/authservice
COPY authservice /opt/authservice/bin/
RUN ln -sfT  /opt/authservice/bin/authservice /usr/bin/authservice

COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh"]
