FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y gcc autoconf automake libtool libcap-dev pkg-config

COPY . /src
WORKDIR /src
RUN env NOCONFIGURE=1 ./autogen.sh
RUN make
RUN make install

FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /src /
