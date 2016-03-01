CC=gcc
OPENSSL=../openssl-1.0.2g
INCLUDES=-I$(OPENSSL)/include
CFLAGS=-Wall -g $(INCLUDES)
LIBCRYPTO=$(OPENSSL)/libcrypto.a
LIBSSL=$(OPENSSL)/libssl.a

VERIFYTRUSTTEST=verify_trust_test

DEPS=$(OPENSSL)/libcrypto.a $(OPENSSL)/libssl.a

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(VERIFYTRUSTTEST): $(VERIFYTRUSTTEST).o
	gcc -ldl $(CFLAGS) -o $@ $^ $(LIBCRYPTO) $(LIBSSL)

test: test_verify_trust

test_verify_trust: $(VERIFYTRUSTTEST)
	@echo $(START) $@
	./$(VERIFYTRUSTTEST)

clean:
	rm -f *.o $(VERIFYTRUSTTEST)
