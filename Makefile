.PHONY: build macos clean

build: macos

macos:
	sh scripts/build-macos-app.sh

clean:
	rm -rf dist
