TESTS=null

.PHONY: test
test:
	@for T in ${TESTS}; do \
		cd $${T} && ${MAKE} test && cd ..; \
	done

.PHONY: clean
clean:
	@for T in ${TESTS}; do \
		cd $${T} && ${MAKE} clean && cd ..; \
	done
