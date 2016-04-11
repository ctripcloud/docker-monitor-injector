versioned_so = inject.so.$(shell git log --oneline|head -1|cut -d" " -f 1)

inject.so: $(versioned_so)
	ln -sf $(versioned_so) inject.so

$(versioned_so): inject.c
	gcc -std=c99 -Wall -shared $(CFLAGS) -g -fPIC -Wl,--no-as-needed -ldl inject.c -o $(versioned_so)

.PHONY: clean

clean:
	rm -f *.o *.so inject.so.*

test: inject.so
	./run_tests.sh
