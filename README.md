# hack-new

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## Docker实验环境构建

### Docker镜像与容器管理

```shell
# 根据Dockerfile构建docker镜像
docker build -t jack-test .

# 根据已有的docker镜像构建docker容器
docker run -it  -d --name rose jack-test

# 关闭已经正在运行容器
docker stop rose

# 与已经构建的容器进行交互
docker exec -it rose /bin/bash

# 查看各个容器的运行情况
docker stats

# 查看目前正在运行的容器
docker container ls

# 查看所有已经被创建的容器
docker container ls -a

# 删除被创立的镜像
docker rmi golang:1.21.5

# 删除被创立的容器
docker rm heuristic_shannon
```

### Docker网络管理

```shell
# 列出目前的docker网络
docker network ls

# docker创建网络
docker network create -d bridge naihe-bridge

# docker删除网络
docker network rm naihe-bridge

# docker建立在自定义bridge下的容器
docker run -d --name naihe1 --hostname naihe1 --network naihe-bridge praqma/network-multitool

# docker端口映射
docker run -d -p 8080:8080 --name naihe1 --hostname naihe1 --network naihe-bridge praqma/network-multitool
```
