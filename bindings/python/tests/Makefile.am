MAINTAINERCLEANFILES = Makefile.in
TESTS = #

TESTS_ENVIRONMENT=TOP_SRCDIR=$(top_srcdir)

if PYTHON_ENABLED
TESTS += profiles_tests.py binding_tests.py
endif

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)

EXTRA_DIST = profiles_tests.py binding_tests.py tests.py XmlTestRunner.py
