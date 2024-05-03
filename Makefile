.PHONY: build build_env test clean all

build_env:
	docker-compose up -d 

build:
	echo "Build BDU parser"
	cargo build --release

test: build
	echo "Run tests"
	docker-compose up -d
	RUST_LOG=debug cargo test test_postgres --verbose
	RUST_LOG=debug cargo test --package bdu_parser --lib -- tests --nocapture
	docker-compose stop

clean:
	cargo clean
	docker-compose stop
	docker-compose rm 

all: build test
