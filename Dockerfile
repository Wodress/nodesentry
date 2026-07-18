FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY nodesentry ./nodesentry
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93
RUN groupadd --system nodesentry && useradd --system --gid nodesentry --home /nonexistent --shell /usr/sbin/nologin nodesentry
COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER nodesentry:nodesentry
ENTRYPOINT ["nodesentry"]
CMD ["audit", "--data-dir", "/disk-probe", "--cookie-file", "/run/secrets/bitcoin-rpc-cookie"]
