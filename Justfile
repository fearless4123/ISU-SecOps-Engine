set shell := ["powershell.exe", "-c"]

# Justfile - Command runner for Qicro development

_default:
    @just --list

# Format all code including TOML
fmt:
    cargo fmt --all
    taplo format

# Run clippy lints
lint:
    cargo clippy --all-targets -- -D warnings

# Run tests
test:
    cargo test --workspace

# Check for security vulnerabilities and licenses
audit:
    cargo deny check

# Build the project
build:
    cargo build --workspace

# Database schema migrations refresh (SeaORM)
db-refresh:
    sea-orm-cli migrate refresh -d migration

# Run the full local CI gate manually
ci: fmt lint audit test build
    @echo "✅ All local CI checks passed!"
