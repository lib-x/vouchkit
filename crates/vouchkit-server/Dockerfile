# Build with the repository root as the context.
FROM rust:1.89-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p vouchkit-server

FROM debian:bookworm-slim
RUN install -d -o 10001 -g 10001 /config /data
COPY --from=build /src/target/release/vouchkit-server /usr/local/bin/vouchkit-server
USER 10001:10001
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["vouchkit-server"]
CMD ["--config", "/config/config.toml"]
