all: helloWorld invertString networkSniffer

helloWorld:
	cc helloWorld.c -o helloWorld

invertString:
	cc invertString.c -o invertString

networkSniffer:
	cc networkSniffer.c -o networkSniffer

clean:
	rm -f helloWorld invertString networkSniffer
