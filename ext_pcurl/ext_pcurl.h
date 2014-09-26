/*
   +----------------------------------------------------------------------+
   | HipHop for PHP                                                       |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010-2014 Facebook, Inc. (http://www.facebook.com)     |
   | Copyright (c) 1997-2010 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/

#ifndef incl_HPHP_EXT_PCURL_H_
#define incl_HPHP_EXT_PCURL_H_

#include "hphp/runtime/base/base-includes.h"

namespace HPHP {
///////////////////////////////////////////////////////////////////////////////

#if LIBCURL_VERSION_NUM >= 0x071500
extern const int64_t k_PCURLINFO_LOCAL_PORT;
#endif
#if LIBCURL_VERSION_NUM >= 0x071002
extern const int64_t k_PCURLOPT_TIMEOUT_MS;
extern const int64_t k_PCURLOPT_CONNECTTIMEOUT_MS;
#endif

extern const int64_t k_PCURLAUTH_ANY;
extern const int64_t k_PCURLAUTH_ANYSAFE;
extern const int64_t k_PCURLAUTH_BASIC;
extern const int64_t k_PCURLAUTH_DIGEST;
extern const int64_t k_PCURLAUTH_GSSNEGOTIATE;
extern const int64_t k_PCURLAUTH_NTLM;
extern const int64_t k_PCURLCLOSEPOLICY_CALLBACK;
extern const int64_t k_PCURLCLOSEPOLICY_LEAST_RECENTLY_USED;
extern const int64_t k_PCURLCLOSEPOLICY_LEAST_TRAFFIC;
extern const int64_t k_PCURLCLOSEPOLICY_OLDEST;
extern const int64_t k_PCURLCLOSEPOLICY_SLOWEST;
extern const int64_t k_PCURLE_ABORTED_BY_CALLBACK;
extern const int64_t k_PCURLE_BAD_CALLING_ORDER;
extern const int64_t k_PCURLE_BAD_CONTENT_ENCODING;
extern const int64_t k_PCURLE_BAD_FUNCTION_ARGUMENT;
extern const int64_t k_PCURLE_BAD_PASSWORD_ENTERED;
extern const int64_t k_PCURLE_COULDNT_CONNECT;
extern const int64_t k_PCURLE_COULDNT_RESOLVE_HOST;
extern const int64_t k_PCURLE_COULDNT_RESOLVE_PROXY;
extern const int64_t k_PCURLE_FAILED_INIT;
extern const int64_t k_PCURLE_FILESIZE_EXCEEDED;
extern const int64_t k_PCURLE_FILE_COULDNT_READ_FILE;
extern const int64_t k_PCURLE_FTP_ACCESS_DENIED;
extern const int64_t k_PCURLE_FTP_BAD_DOWNLOAD_RESUME;
extern const int64_t k_PCURLE_FTP_CANT_GET_HOST;
extern const int64_t k_PCURLE_FTP_CANT_RECONNECT;
extern const int64_t k_PCURLE_FTP_COULDNT_GET_SIZE;
extern const int64_t k_PCURLE_FTP_COULDNT_RETR_FILE;
extern const int64_t k_PCURLE_FTP_COULDNT_SET_ASCII;
extern const int64_t k_PCURLE_FTP_COULDNT_SET_BINARY;
extern const int64_t k_PCURLE_FTP_COULDNT_STOR_FILE;
extern const int64_t k_PCURLE_FTP_COULDNT_USE_REST;
extern const int64_t k_PCURLE_FTP_PORT_FAILED;
extern const int64_t k_PCURLE_FTP_QUOTE_ERROR;
extern const int64_t k_PCURLE_FTP_SSL_FAILED;
extern const int64_t k_PCURLE_FTP_USER_PASSWORD_INCORRECT;
extern const int64_t k_PCURLE_FTP_WEIRD_227_FORMAT;
extern const int64_t k_PCURLE_FTP_WEIRD_PASS_REPLY;
extern const int64_t k_PCURLE_FTP_WEIRD_PASV_REPLY;
extern const int64_t k_PCURLE_FTP_WEIRD_SERVER_REPLY;
extern const int64_t k_PCURLE_FTP_WEIRD_USER_REPLY;
extern const int64_t k_PCURLE_FTP_WRITE_ERROR;
extern const int64_t k_PCURLE_FUNCTION_NOT_FOUND;
extern const int64_t k_PCURLE_GOT_NOTHING;
extern const int64_t k_PCURLE_HTTP_NOT_FOUND;
extern const int64_t k_PCURLE_HTTP_PORT_FAILED;
extern const int64_t k_PCURLE_HTTP_POST_ERROR;
extern const int64_t k_PCURLE_HTTP_RANGE_ERROR;
extern const int64_t k_PCURLE_LDAP_CANNOT_BIND;
extern const int64_t k_PCURLE_LDAP_INVALID_URL;
extern const int64_t k_PCURLE_LDAP_SEARCH_FAILED;
extern const int64_t k_PCURLE_LIBRARY_NOT_FOUND;
extern const int64_t k_PCURLE_MALFORMAT_USER;
extern const int64_t k_PCURLE_OBSOLETE;
extern const int64_t k_PCURLE_OK;
extern const int64_t k_PCURLE_OPERATION_TIMEOUTED;
extern const int64_t k_PCURLE_OUT_OF_MEMORY;
extern const int64_t k_PCURLE_PARTIAL_FILE;
extern const int64_t k_PCURLE_READ_ERROR;
extern const int64_t k_PCURLE_RECV_ERROR;
extern const int64_t k_PCURLE_SEND_ERROR;
extern const int64_t k_PCURLE_SHARE_IN_USE;
extern const int64_t k_PCURLE_SSL_CACERT;
extern const int64_t k_PCURLE_SSL_CERTPROBLEM;
extern const int64_t k_PCURLE_SSL_CIPHER;
extern const int64_t k_PCURLE_SSL_CONNECT_ERROR;
extern const int64_t k_PCURLE_SSL_ENGINE_NOTFOUND;
extern const int64_t k_PCURLE_SSL_ENGINE_SETFAILED;
extern const int64_t k_PCURLE_SSL_PEER_CERTIFICATE;
extern const int64_t k_PCURLE_TELNET_OPTION_SYNTAX;
extern const int64_t k_PCURLE_TOO_MANY_REDIRECTS;
extern const int64_t k_PCURLE_UNKNOWN_TELNET_OPTION;
extern const int64_t k_PCURLE_UNSUPPORTED_PROTOCOL;
extern const int64_t k_PCURLE_URL_MALFORMAT;
extern const int64_t k_PCURLE_URL_MALFORMAT_USER;
extern const int64_t k_PCURLE_WRITE_ERROR;
extern const int64_t k_PCURLFTPAUTH_DEFAULT;
extern const int64_t k_PCURLFTPAUTH_SSL;
extern const int64_t k_PCURLFTPAUTH_TLS;
extern const int64_t k_PCURLFTPSSL_ALL;
extern const int64_t k_PCURLFTPSSL_CONTROL;
extern const int64_t k_PCURLFTPSSL_NONE;
extern const int64_t k_PCURLFTPSSL_TRY;
extern const int64_t k_PCURLINFO_CONNECT_TIME;
extern const int64_t k_PCURLINFO_CONTENT_LENGTH_DOWNLOAD;
extern const int64_t k_PCURLINFO_CONTENT_LENGTH_UPLOAD;
extern const int64_t k_PCURLINFO_CONTENT_TYPE;
extern const int64_t k_PCURLINFO_EFFECTIVE_URL;
extern const int64_t k_PCURLINFO_FILETIME;
extern const int64_t k_PCURLINFO_HEADER_OUT;
extern const int64_t k_PCURLINFO_HEADER_SIZE;
extern const int64_t k_PCURLINFO_HTTP_CODE;
extern const int64_t k_PCURLINFO_NAMELOOKUP_TIME;
extern const int64_t k_PCURLINFO_PRETRANSFER_TIME;
extern const int64_t k_PCURLINFO_PRIVATE;
extern const int64_t k_PCURLINFO_REDIRECT_COUNT;
extern const int64_t k_PCURLINFO_REDIRECT_TIME;
extern const int64_t k_PCURLINFO_REQUEST_SIZE;
extern const int64_t k_PCURLINFO_SIZE_DOWNLOAD;
extern const int64_t k_PCURLINFO_SIZE_UPLOAD;
extern const int64_t k_PCURLINFO_SPEED_DOWNLOAD;
extern const int64_t k_PCURLINFO_SPEED_UPLOAD;
extern const int64_t k_PCURLINFO_SSL_VERIFYRESULT;
extern const int64_t k_PCURLINFO_STARTTRANSFER_TIME;
extern const int64_t k_PCURLINFO_TOTAL_TIME;
extern const int64_t k_PCURLMSG_DONE;
extern const int64_t k_PCURLM_BAD_EASY_HANDLE;
extern const int64_t k_PCURLM_BAD_HANDLE;
extern const int64_t k_PCURLM_CALL_MULTI_PERFORM;
extern const int64_t k_PCURLM_INTERNAL_ERROR;
extern const int64_t k_PCURLM_OK;
extern const int64_t k_PCURLM_OUT_OF_MEMORY;
extern const int64_t k_PCURLOPT_AUTOREFERER;
extern const int64_t k_PCURLOPT_BINARYTRANSFER;
extern const int64_t k_PCURLOPT_BUFFERSIZE;
extern const int64_t k_PCURLOPT_CAINFO;
extern const int64_t k_PCURLOPT_CAPATH;
extern const int64_t k_PCURLOPT_CLOSEPOLICY;
extern const int64_t k_PCURLOPT_CONNECTTIMEOUT;
extern const int64_t k_PCURLOPT_COOKIE;
extern const int64_t k_PCURLOPT_COOKIEFILE;
extern const int64_t k_PCURLOPT_COOKIEJAR;
extern const int64_t k_PCURLOPT_COOKIESESSION;
extern const int64_t k_PCURLOPT_CRLF;
extern const int64_t k_PCURLOPT_CUSTOMREQUEST;
extern const int64_t k_PCURLOPT_DNS_CACHE_TIMEOUT;
extern const int64_t k_PCURLOPT_DNS_USE_GLOBAL_CACHE;
extern const int64_t k_PCURLOPT_EGDSOCKET;
extern const int64_t k_PCURLOPT_ENCODING;
extern const int64_t k_PCURLOPT_FAILONERROR;
extern const int64_t k_PCURLOPT_FILE;
extern const int64_t k_PCURLOPT_FILETIME;
extern const int64_t k_PCURLOPT_FOLLOWLOCATION;
extern const int64_t k_PCURLOPT_FORBID_REUSE;
extern const int64_t k_PCURLOPT_FRESH_CONNECT;
extern const int64_t k_PCURLOPT_FTPAPPEND;
extern const int64_t k_PCURLOPT_FTPLISTONLY;
extern const int64_t k_PCURLOPT_FTPPORT;
extern const int64_t k_PCURLOPT_FTPSSLAUTH;
extern const int64_t k_PCURLOPT_FTP_CREATE_MISSING_DIRS;
extern const int64_t k_PCURLOPT_FTP_SSL;
extern const int64_t k_PCURLOPT_FTP_USE_EPRT;
extern const int64_t k_PCURLOPT_FTP_USE_EPSV;
extern const int64_t k_PCURLOPT_HEADER;
extern const int64_t k_PCURLOPT_HEADERFUNCTION;
extern const int64_t k_PCURLOPT_HTTP200ALIASES;
extern const int64_t k_PCURLOPT_HTTPAUTH;
extern const int64_t k_PCURLOPT_HTTPGET;
extern const int64_t k_PCURLOPT_HTTPHEADER;
extern const int64_t k_PCURLOPT_HTTPPROXYTUNNEL;
extern const int64_t k_PCURLOPT_HTTP_VERSION;
extern const int64_t k_PCURLOPT_INFILE;
extern const int64_t k_PCURLOPT_INFILESIZE;
extern const int64_t k_PCURLOPT_INTERFACE;
extern const int64_t k_PCURLOPT_IPRESOLVE;
extern const int64_t k_PCURLOPT_KRB4LEVEL;
extern const int64_t k_PCURLOPT_LOW_SPEED_LIMIT;
extern const int64_t k_PCURLOPT_LOW_SPEED_TIME;
extern const int64_t k_PCURLOPT_MAXCONNECTS;
extern const int64_t k_PCURLOPT_MAXREDIRS;
extern const int64_t k_PCURLOPT_MUTE;
extern const int64_t k_PCURLOPT_NETRC;
extern const int64_t k_PCURLOPT_NOBODY;
extern const int64_t k_PCURLOPT_NOPROGRESS;
extern const int64_t k_PCURLOPT_NOSIGNAL;
extern const int64_t k_PCURLOPT_PASSWDFUNCTION;
extern const int64_t k_PCURLOPT_PORT;
extern const int64_t k_PCURLOPT_POST;
extern const int64_t k_PCURLOPT_POSTFIELDS;
extern const int64_t k_PCURLOPT_POSTREDIR;
extern const int64_t k_PCURLOPT_POSTQUOTE;
extern const int64_t k_PCURLOPT_PRIVATE;
extern const int64_t k_PCURLOPT_PROGRESSDATA;
extern const int64_t k_PCURLOPT_PROGRESSFUNCTION;
extern const int64_t k_PCURLOPT_PROXY;
extern const int64_t k_PCURLOPT_PROXYAUTH;
extern const int64_t k_PCURLOPT_PROXYPORT;
extern const int64_t k_PCURLOPT_PROXYTYPE;
extern const int64_t k_PCURLOPT_PROXYUSERPWD;
extern const int64_t k_PCURLOPT_PUT;
extern const int64_t k_PCURLOPT_QUOTE;
extern const int64_t k_PCURLOPT_RANDOM_FILE;
extern const int64_t k_PCURLOPT_RANGE;
extern const int64_t k_PCURLOPT_READDATA;
extern const int64_t k_PCURLOPT_READFUNCTION;
extern const int64_t k_PCURLOPT_REFERER;
extern const int64_t k_PCURLOPT_RESUME_FROM;
extern const int64_t k_PCURLOPT_RETURNTRANSFER;
extern const int64_t k_PCURLOPT_SSLCERT;
extern const int64_t k_PCURLOPT_SSLCERTPASSWD;
extern const int64_t k_PCURLOPT_SSLCERTTYPE;
extern const int64_t k_PCURLOPT_SSLENGINE;
extern const int64_t k_PCURLOPT_SSLENGINE_DEFAULT;
extern const int64_t k_PCURLOPT_SSLKEY;
extern const int64_t k_PCURLOPT_SSLKEYPASSWD;
extern const int64_t k_PCURLOPT_SSLKEYTYPE;
extern const int64_t k_PCURLOPT_SSLVERSION;
extern const int64_t k_PCURLOPT_SSL_CIPHER_LIST;
extern const int64_t k_PCURLOPT_SSL_VERIFYHOST;
extern const int64_t k_PCURLOPT_SSL_VERIFYPEER;
extern const int64_t k_PCURLOPT_STDERR;
extern const int64_t k_PCURLOPT_TCP_NODELAY;
extern const int64_t k_PCURLOPT_TIMECONDITION;
extern const int64_t k_PCURLOPT_TIMEOUT;
extern const int64_t k_PCURLOPT_TIMEVALUE;
extern const int64_t k_PCURLOPT_TRANSFERTEXT;
extern const int64_t k_PCURLOPT_UNRESTRICTED_AUTH;
extern const int64_t k_PCURLOPT_UPLOAD;
extern const int64_t k_PCURLOPT_URL;
extern const int64_t k_PCURLOPT_USERAGENT;
extern const int64_t k_PCURLOPT_USERPWD;
extern const int64_t k_PCURLOPT_VERBOSE;
extern const int64_t k_PCURLOPT_WRITEFUNCTION;
extern const int64_t k_PCURLOPT_WRITEHEADER;
extern const int64_t k_PCURLPROXY_HTTP;
extern const int64_t k_PCURLPROXY_SOCKS5;
extern const int64_t k_PCURLVERSION_NOW;
extern const int64_t k_PCURL_HTTP_VERSION_1_0;
extern const int64_t k_PCURL_HTTP_VERSION_1_1;
extern const int64_t k_PCURL_HTTP_VERSION_NONE;
extern const int64_t k_PCURL_IPRESOLVE_V4;
extern const int64_t k_PCURL_IPRESOLVE_V6;
extern const int64_t k_PCURL_IPRESOLVE_WHATEVER;
extern const int64_t k_PCURL_NETRC_IGNORED;
extern const int64_t k_PCURL_NETRC_OPTIONAL;
extern const int64_t k_PCURL_NETRC_REQUIRED;
extern const int64_t k_PCURL_TIMECOND_IFMODSINCE;
extern const int64_t k_PCURL_TIMECOND_IFUNMODSINCE;
extern const int64_t k_PCURL_TIMECOND_LASTMOD;
extern const int64_t k_PCURL_VERSION_IPV6;
extern const int64_t k_PCURL_VERSION_KERBEROS4;
extern const int64_t k_PCURL_VERSION_LIBZ;
extern const int64_t k_PCURL_VERSION_SSL;


String HHVM_FUNCTION(pcurl_pool_stats);
bool HHVM_FUNCTION(pcurl_pool_reset);
void HHVM_FUNCTION(pcurl_trace_log, const String& msg);
Variant HHVM_FUNCTION(pcurl_init, const Variant& url = null_string);
Variant HHVM_FUNCTION(pcurl_copy_handle, const Resource& ch);
Variant HHVM_FUNCTION(pcurl_version, int uversion = k_PCURLVERSION_NOW);
bool HHVM_FUNCTION(pcurl_setopt, const Resource& ch, int option, const Variant& value);
bool HHVM_FUNCTION(pcurl_setopt_array, const Resource& ch, const Array& options);
Variant HHVM_FUNCTION(fb_pcurl_getopt, const Resource& ch, int64_t opt = 0);
Variant HHVM_FUNCTION(pcurl_exec, const Resource& ch);
Variant HHVM_FUNCTION(pcurl_getinfo, const Resource& ch, int opt = 0);
Variant HHVM_FUNCTION(pcurl_errno, const Resource& ch);
Variant HHVM_FUNCTION(pcurl_error, const Resource& ch);
Variant HHVM_FUNCTION(pcurl_close, const Resource& ch);
void HHVM_FUNCTION(pcurl_reset, const Resource& ch);
Resource HHVM_FUNCTION(pcurl_multi_init);
Variant HHVM_FUNCTION(pcurl_multi_add_handle, const Resource& mh, const Resource& ch);
Variant HHVM_FUNCTION(pcurl_multi_remove_handle, const Resource& mh, const Resource& ch);
Variant HHVM_FUNCTION(pcurl_multi_exec, const Resource& mh, VRefParam still_running);
Variant HHVM_FUNCTION(pcurl_multi_select, const Resource& mh, double timeout = 1.0);
Variant HHVM_FUNCTION(pcurl_multi_getcontent, const Resource& ch);
Variant HHVM_FUNCTION(fb_pcurl_multi_fdset, const Resource& mh,
                              VRefParam read_fd_set,
                              VRefParam write_fd_set,
                              VRefParam exc_fd_set,
                              VRefParam max_fd = null_object);
Variant HHVM_FUNCTION(pcurl_multi_info_read, const Resource& mh,
                               VRefParam msgs_in_queue = null_object);
Variant HHVM_FUNCTION(pcurl_multi_close, const Resource& mh);

///////////////////////////////////////////////////////////////////////////////
}

#endif // incl_HPHP_EXT_PCURL_H_
