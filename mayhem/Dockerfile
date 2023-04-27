#FROM --platform=linux/amd64 ubuntu:22.04 as builder
FROM fuzzers/libfuzzer:12.0 as builder

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y gcc autoconf automake libtool libcap-dev pkg-config make clang

COPY . /src
WORKDIR /src
RUN ./autogen.sh && make && make install


#FROM fuzzers/libfuzzer:12.0
#COPY --from=builder /src /

