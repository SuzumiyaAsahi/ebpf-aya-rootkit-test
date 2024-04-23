FROM ubuntu:latest

# 不交互，静默安装
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
  build-essential \
  curl \
  git \
  vim \
  iproute2

RUN apt-get clean

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustup update nightly && \
  rustup default nightly

RUN cargo install bpf-linker
