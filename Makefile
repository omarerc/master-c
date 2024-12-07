all: helloWorld invertString networkSniffer

helloWorld:
	cc helloWorld.c -o helloWorld

invertString:
	cc invertString.c -o invertString

networkSniffer:
	cc networkSniffer.c -o networkSniffer

.PHONY: clean
clean:
	rm -f helloWorld invertString networkSniffer
