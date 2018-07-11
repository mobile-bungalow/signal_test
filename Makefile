

make: *.o
	gcc *.o -o signal_test -lsignal-protocol-c -lm -lssl -lcrypto -lm

*.o: *.c
	gcc -c *.c -lsignal-protocol-c -lm

clean:
	rm -f *.o
	rm -f *.gch
