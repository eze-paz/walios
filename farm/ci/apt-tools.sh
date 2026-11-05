# Build-host packages for the farm. The plan job (farm.yml) downloads their debs once into
# ~/aptc, cached for the run's build jobs, which install them offline (farm-wave.yml): R43 lost
# 9 of 59 jobs to apt stalls of 30 minutes on both Ubuntu mirrors, and each held its wave.
APT_TOOLS="autoconf automake libtool autopoint pkgconf bison flex gettext texinfo gperf help2man meson ninja-build cmake fakeroot autotools-dev autoconf-archive libarchive-tools lzip unzip xmlto asciidoc-base scons lua5.4 python3-docutils docbook-xsl xsltproc"
# Doc and code-generation tools some recipes run on the build host (the R39 triage: doxygen,
# po4a, sphinx-build, protoc, googletest sources, qjs, muon, docbook2x, a2x). Best effort,
# one by one: a name this Ubuntu lacks must not fail the job.
APT_OPTIONAL="doxygen po4a python3-sphinx protobuf-compiler googletest libgtest-dev quickjs muon-meson muon docbook2x asciidoc"
