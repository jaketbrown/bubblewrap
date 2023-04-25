FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y gcc autoconf pkg-config libcap

COPY . /src
WORKDIR /src
RUN ./autogen.sh
RUN make
RUN sudo make install

FROM --platform=linux/amd64 ubuntu:20.04
COPY --from=builder /src /
