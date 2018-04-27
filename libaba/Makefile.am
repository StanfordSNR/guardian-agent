AM_CPPFLAGS = $(CXX17_FLAGS) -fPIC -I$(top_builddir)/proto -I$(top_srcdir)
AM_CXXFLAGS = $(PICKY_CXXFLAGS)

lib_LTLIBRARIES = libhooks.la

libhooks_la_LDFLAGS = -shared -module  -lsyscall_intercept -lprotobuf -lstdc++fs $(top_builddir)/proto/libguardoproto.la 

libhooks_la_LIBADD = $(top_builddir)/proto/syscalls.o

libhooks_la_SOURCES = util.hh \
	file_descriptor.hh file_descriptor.cc \
	address.hh address.cc \
	hooks.cc \
	marshalls.hh marshalls.cc \
	sendmsg_marshall.hh sendmsg_marshall.cc \
	socket.hh socket.cc \
	poller.hh poller.cc \
	timestamp.hh timestamp.cc \
	util.cc
