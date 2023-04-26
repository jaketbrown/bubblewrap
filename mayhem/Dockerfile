FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y gcc autoconf pkg-config libcap-dev

COPY . /src
WORKDIR /src
RUN ./autogen.sh
RUN make
RUN sudo make install

FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /src /
