CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
LDID = $(shell which ldid)
PYTHON = $(shell which python3)

LIBS = $(SDK)/usr/lib
CFLAGS = -arch arm64 -miphoneos-version-min=9.0

all:
	$(CC) $(CFLAGS) -c ./src/main.s
	$(STRIP) main.o
	./tools/make_bin.sh main.o
	$(PYTHON) ./tools/bin_to_js.py loader
	cp -a ./src/main.js ./output.js
	cat ./shellcode.js >> ./output.js
	rm -rf shellcode.js
	rm -rf loader

clean:
	@rm -rf main.o
	@rm -rf shellcode.js
	@rm -rf output.js
	@rm -rf loader
