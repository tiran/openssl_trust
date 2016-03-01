OPENSSL_TARGZ=https://openssl.org/source/openssl-1.0.2g.tar.gz
OPENSSL=openssl-1.0.2g

.PHONY=all tests clean

all: tests

$(OPENSSL):
	@echo
	@echo "Download $(OPENSSL_TARGZ)_and compile it with default settings."
	@echo
	@exit 1

tests: $(OPENSSL)
	$(MAKE) -C test test OPENSSL=$(CURDIR)/$(OPENSSL)

clean:
	$(MAKE) -C test clean
