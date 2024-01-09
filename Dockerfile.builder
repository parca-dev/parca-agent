FROM jetpackio/devbox:latest

# Installing your devbox project.
WORKDIR /code
USER ${DEVBOX_USER}:${DEVBOX_USER}

COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.json devbox.json
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.lock devbox.lock
RUN devbox install

# Make sure init hooks are executed.
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} install-tools* .
RUN devbox run -- echo "All the packages are installed."

RUN devbox shellenv --init-hook >> ~/.profile
RUN devbox shellenv --init-hook >> ~/.bashrc
ENTRYPOINT ["/bin/bash", "-l", "-c"]
