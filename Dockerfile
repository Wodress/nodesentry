FROM python:3.11-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY nodesentry ./nodesentry
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.11-slim
RUN groupadd --system nodesentry && useradd --system --gid nodesentry --home /nonexistent --shell /usr/sbin/nologin nodesentry
COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER nodesentry:nodesentry
ENTRYPOINT ["nodesentry"]
CMD ["audit", "--data-dir", "/bitcoin", "--cookie-file", "/bitcoin/.cookie"]
