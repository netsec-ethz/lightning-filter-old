CFLAGS=-std=c99 -pedantic -pedantic-errors -Werror -Wall -Wextra -fsanitize=undefined

all: null

null: null.c

.PHONY: test
test: null
	@./null

.PHONY: clean
clean:
	rm -f null
