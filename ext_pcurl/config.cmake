HHVM_DEFINE_EXTENSION("pcurl"
  SOURCES
    ext_pcurl.cpp
  HEADERS
    ext_pcurl.h
  SYSTEMLIB
    ext_pcurl.php
  DEPENDS
    libBoost
    libCurl
    libFolly
    libOpenSSL
)
