RUN_USERNS := lxc-usernsexec -m "u:0:`id -u`:1" -m "g:0:`id -g`:1" --

all: test

test: test_setup test_snapshot test_bindmount test_idmap test_bpfdelegate test_exec_concurrency test_hostnic

test_setup: run_setup_tests.pl
	if test -e /run/lock/sbuild; then \
		echo skipping userns tests in sbuild environment ; \
	else \
		$(RUN_USERNS) ./run_setup_tests.pl ; \
	fi

test_snapshot: run_snapshot_tests.pl
	./run_snapshot_tests.pl

test_bindmount: bindmount_test.pl
	if test -e /run/lock/sbuild; then \
		echo skipping userns tests in sbuild environment ; \
	else \
		$(RUN_USERNS) ./bindmount_test.pl ; \
	fi

test_idmap: run_idmap_tests.pl
	./run_idmap_tests.pl

test_bpfdelegate: bpfdelegate-test.pl
	./bpfdelegate-test.pl

test_exec_concurrency: exec-concurrency-test.pl
	./exec-concurrency-test.pl

test_hostnic: hostnic-test.pl
	./hostnic-test.pl

clean:
	rm -rf tmprootfs
