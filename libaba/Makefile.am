AM_CPPFLAGS = $(CXX17_FLAGS) -fPIC -I$(top_builddir)/proto
AM_CXXFLAGS = $(PICKY_CXXFLAGS)

lib_LTLIBRARIES = libhooks.la

libhooks_la_LDFLAGS = -shared -module  -lsyscall_intercept -lprotobuf -lstdc++fs $(top_builddir)/proto/libguardoproto.la

libhooks_la_SOURCES = util.hh \
	file_descriptor.hh file_descriptor.cc \
	address.hh address.cc \
	hooks.cc \
	socket.hh socket.cc \
	poller.hh poller.cc \
	timestamp.hh timestamp.cc
