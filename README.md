# hack-new

## Run

```bash
make run
```

## sys_enter_read参数读取

```rust
    unsafe {
        // 这些参数都是哪里来的？
        //field:char * buf; offset:24; size:8; signed:0;
        let buff_addr: u64 = ctx.read_at(24).unwrap();

        //field:size_t count; offset:32; size:8; signed:0;
        let size: u64 = ctx.read_at(32).unwrap();

        data.buffer_addr = buff_addr;

        data.calling_size = size;
    }
```

这些参数都是这么来滴！

```bash
# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
name: sys_enter_read
ID: 680
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:char * buf;       offset:24;      size:8; signed:0;
        field:size_t count;     offset:32;      size:8; signed:0;

print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))
```

## Docker实验环境构建

不过这把没用上Docker，内核的东西使用Docker来模拟确实不太好。

暂时还没想到什么太好的方法。

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

## VM虚拟机补充

```shell
# 安装VM增强工具（多少对VirtualBox有点哀其不幸，怒其不争了。）
sudo apt install open-vm-tools
sudo apt install open-vm-tools-desktop
```
