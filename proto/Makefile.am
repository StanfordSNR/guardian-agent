source = guardo.proto guardian_agent.proto

SUFFIXES = .proto .pb.cc

AM_CPPFLAGS = $(CXX17_FLAGS) -shared -fPIC
AM_CXXFLAGS = $(PICKY_CXXFLAGS)

.proto.pb.cc:
	$(PROTOC) --cpp_out=$(builddir) --go_out=$(top_srcdir) -I$(srcdir) $(srcdir)/*.proto

noinst_LTLIBRARIES = libguardoproto.la
dist_noinst_DATA = guardo.proto	

libguardoproto_la_SOURCES = $(source)
nodist_libguardoproto_la_SOURCES = $(source:.proto=.pb.cc) $(source:.proto=.pb.h)

BUILT_SOURCES =	$(builddir)/guardo.pb.cc $(builddir)/guardo.pb.h
CLEANFILES = $(source:.proto=.pb.cc) $(source:.proto=.pb.h) $(source:.proto=_pb2.py) $(source:.proto=_pb2.pyc) libguardoproto.la