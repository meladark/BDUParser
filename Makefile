.PHONY: build build_env test clean all

build_env:
	docker-compose up -d 

build:
	echo "Build BDU parser"
	cargo build

test: build
	echo "Run tests"
	docker-compose up -d
	cargo test test_postgres --verbose
	cargo test --package bdu_parser --lib -- tests --nocapture
	docker-compose stop

clean:
	cargo clean
	docker-compose stop
	docker-compose rm 

all: build test
