.PHONY: all build clean test examples

build:
	dune build @install

all: build

test:
	dune runtest

watch:
	dune build {h1,h1-lwt-unix}.install @runtest --watch

install:
	dune install

uninstall:
	dune uninstall

clean:
	rm -rf _build *.install
