FROM jetpackio/devbox:latest

# Installing your devbox project
WORKDIR /code
USER ${DEVBOX_USER}:${DEVBOX_USER}
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.json devbox.json
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.lock devbox.lock

COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} ../install-tools.sh .

RUN devbox run -- echo "All the packages are installed."

RUN devbox shellenv --init-hook >> ~/.profile
ENTRYPOINT [ "devbox", "shell"]
