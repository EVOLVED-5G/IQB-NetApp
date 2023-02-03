FROM quay.io/keycloak/keycloak:15.0.2

USER root
RUN mkdir -p /tmp/import
COPY realm-export.json /tmp/import
RUN chown jboss:jboss /tmp/import
USER jboss

ENTRYPOINT [ "/opt/jboss/tools/docker-entrypoint.sh" ]
CMD ["-b", "0.0.0.0"]
