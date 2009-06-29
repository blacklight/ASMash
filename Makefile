SRCDIR=src
INCLUDEDIR=include
PREFIX=/usr/local
LIB=elfshark
OPTS=-Wall -pedantic

all:
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/decode.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/elf.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/op_bits8.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/op_jmp.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/op_pushpop.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/op_reg32.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/op_scal32.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/op_scal81.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/single.c
	gcc $(OPTS) -I$(INCLUDEDIR) -fPIC -g -c $(SRCDIR)/utils.c
	gcc -shared -Wl,-soname,lib$(LIB).so.0 -o lib$(LIB).so.0.0.0 *.o
	ar rcs lib$(LIB).a *.o

install:
	mkdir -p $(PREFIX)/lib
	mkdir -p $(PREFIX)/doc
	mkdir -p $(PREFIX)/doc/$(LIB)-$(shell cat VERSION)
	mkdir -p $(PREFIX)/$(INCLUDEDIR)
	install -m 0644 README  $(PREFIX)/doc/$(LIB)-$(shell cat VERSION)
	install -m 0644 INSTALL $(PREFIX)/doc/$(LIB)-$(shell cat VERSION)
	install -m 0644 VERSION $(PREFIX)/doc/$(LIB)-$(shell cat VERSION)
	install -m 0644 LICENCE $(PREFIX)/doc/$(LIB)-$(shell cat VERSION)
	install -m 0644 $(INCLUDEDIR)/elfshark.h $(PREFIX)/include
	install -m 0644 lib$(LIB).a $(PREFIX)/lib
	install -m 0755 lib$(LIB).so.0.0.0 $(PREFIX)/lib
	ln -sf $(PREFIX)/lib/lib$(LIB).so.0.0.0 $(PREFIX)/lib/lib$(LIB).so.0
	ldconfig

clean:
	rm *.o
	rm lib$(LIB).a
	rm lib$(LIB).so.*

uninstall:
	rm $(PREFIX)/include/elfshark.h
	rm $(PREFIX)/lib/lib$(LIB).so.*
	rm $(PREFIX)/lib/lib$(LIB).a
