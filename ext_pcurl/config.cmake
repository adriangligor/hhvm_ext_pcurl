include_directories("../hhvm-3.2-include")

HHVM_EXTENSION(pcurl ext_pcurl.cpp)
HHVM_SYSTEMLIB(pcurl ext_pcurl.php)
