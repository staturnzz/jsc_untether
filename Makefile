CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
LDID = $(shell which ldid)
PYTHON = $(shell which python3)

LIBS = $(SDK)/usr/lib
CFLAGS = -miphoneos-version-min=7.0

arm64:
	$(CC) -arch arm64 $(CFLAGS) -c ./src/main_arm64.s
	$(STRIP) main_arm64.o
	./tools/make_bin.sh main_arm64.o
	$(PYTHON) ./tools/bin_to_js.py loader arm64
	cp -a ./src/main_arm64.js ./output_arm64.js
	cat ./shellcode.js >> ./output_arm64.js
	rm -rf shellcode.js
	rm -rf loader

armv7:
	$(CC) -arch armv7 $(CFLAGS) -c ./src/main_armv7.s
	$(STRIP) main_armv7.o
	./tools/make_bin.sh main_armv7.o
	$(PYTHON) ./tools/bin_to_js.py loader armv7
	cp -a ./src/main_armv7.js ./output_armv7.js
	cat ./shellcode.js >> ./output_armv7.js
	rm -rf shellcode.js
	rm -rf loader

all: clean arm64 armv7

clean:
	@rm -rf main.o
	@rm -rf main_armv7.o
	@rm -rf main_arm64.o
	@rm -rf shellcode.js
	@rm -rf output.js
	@rm -rf output_armv7.js
	@rm -rf output_arm64.js
	@rm -rf loader
