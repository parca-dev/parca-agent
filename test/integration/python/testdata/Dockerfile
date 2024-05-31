ARG PY_IMAGE

# hadolint ignore=DL3006
FROM $PY_IMAGE

# hadolint ignore=DL3018
RUN if [ -x "$(command -v apk)" ]; then apk update; apk upgrade musl; apk --no-cache add musl-dbg; fi

COPY cpu_hog.py /test.py

CMD ["python", "/test.py"]
