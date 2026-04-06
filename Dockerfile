# Build stage
FROM rust:1.75 as builder
WORKDIR /app

# Sadece bağımlılıkları derle ki cache'lensin
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Kendi kodumuzu kopyala ve asıl projeyi derle
COPY . .
# Önceki aptal main'i sildiğimizden emin olalım ki target klasörü değiştiğini anlasın (Rust'ta mtime trick gerekebilir)
RUN touch src/main.rs || true
RUN cargo build --release

# Run stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/aegis-tls /app/aegis-tls
EXPOSE 8080
ENTRYPOINT ["/app/aegis-tls"]
CMD ["web", "--port", "8080"]
