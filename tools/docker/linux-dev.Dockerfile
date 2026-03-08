FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        libdbus-1-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:${PATH}
ENV CARGO_TERM_COLOR=always

WORKDIR /work

CMD ["bash"]
