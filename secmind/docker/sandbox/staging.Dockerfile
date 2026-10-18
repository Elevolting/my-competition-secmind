FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092

COPY docker/sandbox/stage.sh /opt/secmind-stage
RUN chmod 0555 /opt/secmind-stage

ENTRYPOINT ["/opt/secmind-stage"]
