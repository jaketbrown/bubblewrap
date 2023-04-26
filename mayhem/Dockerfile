FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y gcc autoconf automake libtool libcap-dev pkg-config make

COPY . /src
WORKDIR /src
RUN ./autogen.sh && make && make install
RUN ls -l

FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /src /
