FROM ghcr.io/astral-sh/uv:python3.13-trixie

COPY ./security-runtime/pyproject.toml /security-runtime/pyproject.toml
COPY ./security-runtime/uv.lock /security-runtime/uv.lock
WORKDIR /security-runtime
RUN uv sync --frozen --no-install-project -i https://mirrors.aliyun.com/pypi/simple/

COPY ./security-runtime /security-runtime
RUN uv sync --frozen -i https://mirrors.aliyun.com/pypi/simple/

ENV TZ=Asia/Shanghai
