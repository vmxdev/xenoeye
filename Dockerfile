FROM gcc:bookworm AS build
RUN apt-get update
RUN apt-get install -y build-essential gcc tclsh libboost-dev libboost-program-options-dev \
      libgtest-dev libpcap-dev pkg-config
WORKDIR /app
COPY . .
RUN autoreconf -i
RUN ./configure --sysconfdir=/etc/xenoeye --localstatedir=/var/lib --libexecdir=/var/lib/xenoeye/scripts
RUN make && make install --no-silent

FROM debian:bookworm-slim AS prod
RUN useradd -u 53842 -rlM -d /nonexistent -s /usr/sbin/nologin user
RUN apt update && apt install -y --no-install-recommends libssl3 libatomic1 libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/xenoeye /usr/local/bin/xemkgeodb /usr/local/bin/xegeoq /usr/local/bin/xesflow /usr/local/bin/xemoclone /usr/local/bin/
COPY --from=build /var/lib/xenoeye /var/lib/xenoeye
COPY --from=build /etc/xenoeye /etc/xenoeye
USER user:user
CMD ["/usr/local/bin/xenoeye"]
