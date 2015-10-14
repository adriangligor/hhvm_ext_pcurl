/*
   +----------------------------------------------------------------------+
   | HipHop for PHP                                                       |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010-2015 Facebook, Inc. (http://www.facebook.com)     |
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

#include "ext_pcurl.h"
#include "hphp/runtime/ext/asio/asio-external-thread-event.h"
#include "hphp/runtime/ext/asio/socket-event.h"
#include "hphp/runtime/base/array-init.h"
#include "hphp/runtime/base/builtin-functions.h"
#include "hphp/runtime/base/plain-file.h"
#include "hphp/runtime/base/string-buffer.h"
#include "hphp/runtime/base/req-ptr.h"
#include "hphp/runtime/base/libevent-http-client.h"
#include "hphp/runtime/base/curl-tls-workarounds.h"
#include "hphp/runtime/base/runtime-option.h"
#include "hphp/runtime/ext/extension-registry.h"
#include "hphp/runtime/server/server-stats.h"
#include "hphp/runtime/vm/jit/translator-inline.h"
#include "hphp/util/lock.h"
#include <boost/algorithm/string.hpp>
#include <boost/variant.hpp>
#include <folly/Optional.h>
#include <openssl/ssl.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#include <memory>
#include <vector>


/* CUSTOM_START */
#include "UriParser.hpp"
#include <sys/poll.h>
#include <iostream>
#include <fstream>
#include <deque>
#include <set>
#include <thread>
#include "hphp/util/logger.h"
/* CUSTOM_END */

#define CURLOPT_RETURNTRANSFER 19913
#define CURLOPT_BINARYTRANSFER 19914
#define CURLOPT_MUTE -2
#define CURLOPT_PASSWDFUNCTION -3
#define PHP_CURL_STDOUT 0
#define PHP_CURL_FILE   1
#define PHP_CURL_USER   2
#define PHP_CURL_DIRECT 3
#define PHP_CURL_RETURN 4
#define PHP_CURL_ASCII  5
#define PHP_CURL_BINARY 6
#define PHP_CURL_IGNORE 7


namespace {
using namespace std::chrono;

#define _LOG(msg) Logger::Info(msg)
//#define _LOG(msg) do {} while (0)

static system_clock::time_point _starttime() {
  return system_clock::now();
}

static float _stoptime(system_clock::time_point starttime) {
  typedef std::chrono::duration<float, std::milli> float_milliseconds;
  auto stoptime = system_clock::now();
  auto duration = duration_cast<float_milliseconds>(stoptime - starttime);
  return duration.count();
}

} // namespace


namespace HPHP {

using std::string;
using std::vector;

namespace {

const StaticString
  s_exception("exception"),
  s_previous("previous");

using ExceptionType = folly::Optional<boost::variant<Object,Exception*>>;

bool isPhpException(const ExceptionType& e) {
  return e && boost::get<Object>(&e.value()) != nullptr;
}

Object getPhpException(const ExceptionType& e) {
  assert(e && isPhpException(e));
  return boost::get<Object>(*e);
}

Exception* getCppException(const ExceptionType& e) {
  assert(e && !isPhpException(e));
  return boost::get<Exception*>(*e);
}

void throwException(ExceptionType&& e) {
  if (isPhpException(e)) {
    throw getPhpException(e);
  } else {
    getCppException(e)->throwException();
  }
}

}

///////////////////////////////////////////////////////////////////////////////
/**
 * This is a helper class used to wrap Curl handles that are pooled.
 * Operations on this class are _NOT_ thread safe!
 */
class PooledPCurlHandle {
public:
  explicit PooledPCurlHandle(int connRecycleAfter)
  : m_handle(nullptr), m_numUsages(0), m_connRecycleAfter(connRecycleAfter) { }

  CURL* useHandle() {
    if (m_handle == nullptr) {
      m_handle = curl_easy_init();
    }

    if (m_connRecycleAfter > 0 &&
        m_numUsages % m_connRecycleAfter == 0) {
      curl_easy_cleanup(m_handle);
      m_handle = curl_easy_init();
      m_numUsages = 0;
    }

    m_numUsages++;
    return m_handle;
  }

  void resetHandle() {
    if (m_handle != nullptr) {
      curl_easy_reset(m_handle);
    }
  }

  ~PooledPCurlHandle() {
    if (m_handle != nullptr) {
      curl_easy_cleanup(m_handle);
    }
  }

private:
  CURL* m_handle;
  int m_numUsages;
  int m_connRecycleAfter;
};

///////////////////////////////////////////////////////////////////////////////
/**
 * This is a helper class used to implement a process-wide pool of libcurl
 * handles. This provides very large performance benefits, as libcurl handles
 * hold connections open and cache SSL session ids over their lifetimes.
 * All operations on this class are thread safe.
 */
class PCurlHandlePool {
public:
  static std::map<std::string, PCurlHandlePool*> namedPools;

  explicit PCurlHandlePool(int poolSize, int waitTimeout, int numConnReuses)
  : m_waitTimeout(waitTimeout) {
    for (int i = 0; i < poolSize; i++) {
      m_handleStack.push(new PooledPCurlHandle(numConnReuses));
    }
    pthread_cond_init(&m_cond, nullptr);
  }

  PooledPCurlHandle* fetch() {
    Lock lock(m_mutex);

    // wait until the user-specified timeout for an available handle
    struct timespec ts;
    gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += m_waitTimeout / 1000;
    ts.tv_nsec += 1000000 * (m_waitTimeout % 1000);
    while (m_handleStack.empty()) {
      if (ETIMEDOUT == pthread_cond_timedwait(&m_cond, &m_mutex.getRaw(), &ts))
      {
        raise_error("Timeout reached waiting for an "
                    "available pooled curl connection!");
      }
    }

    PooledPCurlHandle* ret = m_handleStack.top();
    assert(ret);
    m_handleStack.pop();
    return ret;
  }

  void store(PooledPCurlHandle* handle) {
    Lock lock(m_mutex);
    handle->resetHandle();
    m_handleStack.push(handle);
    pthread_cond_signal(&m_cond);
  }

  ~PCurlHandlePool() {
    Lock lock(m_mutex);
    while (!m_handleStack.empty()) {
      PooledPCurlHandle *handle = m_handleStack.top();
      m_handleStack.pop();
      delete handle;
    }
  }

private:
  std::stack<PooledPCurlHandle*> m_handleStack;
  Mutex m_mutex;
  pthread_cond_t m_cond;
  int m_waitTimeout;
};

std::map<std::string, PCurlHandlePool*> PCurlHandlePool::namedPools;


/* CUSTOM_START */
class SocketFdPool {
private:
  int max;
  std::string hostkey;
  Mutex excl;
  std::deque<curl_socket_t> pool;
  std::set<curl_socket_t> taken;

public:
  explicit SocketFdPool(int max, std::string hostkey) : max(max), hostkey(hostkey) {
    //_LOG("pool: created, max=" + std::to_string(max));
  }

  virtual ~SocketFdPool() {
    //_LOG("pool: destroyed");
    clean();
  }

  std::pair<curl_socket_t, bool> take(curl_sockaddr *addr, int trial = 1) {
    Lock lock(excl);

    curl_socket_t sockfd;
    if (pool.size() > 0 && trial < 3) {
      // there is at least one free socket
      sockfd = pool.front();
      pool.pop_front();

      if (socketAlive(sockfd)) {
        // socket is fine, return it
        taken.insert(sockfd);
        //_LOG("pool: taking existent socket (" + std::to_string(sockfd) +
        //  ") - " + stats());
        return std::make_pair(sockfd, true);
      }

      // this socket is dead, dispose of it, and try another one
      close(sockfd);
      return take(addr, trial + 1);
    } else if (taken.size() < max) {
      // there is no free socket, but we're allowed to create one and return it
      sockfd = socket(addr->family, addr->socktype, addr->protocol);
      if (sockfd != CURL_SOCKET_BAD) taken.insert(sockfd);
      //_LOG("pool: creating new socket (" + std::to_string(sockfd) +
      //  ") - " + stats());
      return std::make_pair(sockfd, false);
    }

    // the maximum amount of sockets have been taken, return error
    //_LOG("pool: max sockets reached - " + stats());
    return std::make_pair(CURL_SOCKET_BAD, false);
  }

  void putback(curl_socket_t sockfd) {
    Lock lock(excl);

    pool.push_back(sockfd);
    taken.erase(sockfd);
    //_LOG("pool: returned socket (" + std::to_string(sockfd) + ") - " + stats());
  }

  bool clean() {
    Lock lock(excl);

    for (auto it = pool.begin(); it != pool.end(); /* nothing */) {
      curl_socket_t sockfd = *it;
      if (!socketAlive(sockfd) && (close(sockfd) >= -1)) { // close always >= -1
        it = pool.erase(it);
      } else {
        ++it;
      }
    }

    //_LOG("pool: reset - " + stats());
    return (pool.size() + taken.size() == 0); // true when pool really is empty
  }

  std::string stats() {
    return "free: " + std::to_string(pool.size()) +
      ", taken: " + std::to_string(taken.size());
  }

  std::map<std::string, int> statsMap() {
    std::map<std::string, int> stats;

    stats["free"] = pool.size();
    stats["taken"] = taken.size();

    return stats;
  }

private:
  bool socketAlive(curl_socket_t sockfd) {
    struct pollfd pfd;
    int poll_status;

    pfd.fd = sockfd;
    pfd.events = POLLRDNORM | POLLIN | POLLRDBAND | POLLPRI; // read tests
    //pfd.events = POLLWRNORM | POLLOUT; // write tests
    pfd.revents = 0;

    // the following code issues a poll with timeout 0. it either returns
    // instantly, because no operation can be done within a 0 timeout,
    // or returns an error, because the socket is known to be dead
    do {
      // do a poll with timeout 0 (no waiting)
      poll_status = poll(&pfd, 1, 0);
      if ((poll_status != -1) || (errno && errno != EINTR)) {
        // the poll wasn't interrupted and returned success or an error
        break;
      }
    } while (poll_status == -1); // loop until a non-interrupted poll

    return (poll_status == 0); // "timeout" means the socket is alive
  }
};

class HostSocketFdPool {
private:
  int max;
  int cleanupIntervalSec;
  Mutex excl;
  std::atomic<bool> doCleanup;
  std::thread cleanup;
  std::unordered_map<std::string, std::shared_ptr<SocketFdPool>> pools;
  std::unordered_map<curl_socket_t, std::shared_ptr<SocketFdPool>> taken;

public:
  explicit HostSocketFdPool(int max, int cleanupIntervalSec) :
    max(max), cleanupIntervalSec(cleanupIntervalSec), doCleanup(true),
    cleanup(&HostSocketFdPool::periodicCleanup, this)
  {
    //_LOG("hpool: created, max=" + std::to_string(max) + ", cleanup=" +
    //  std::to_string(cleanupIntervalSec) + "sec");
  }

  virtual ~HostSocketFdPool() {
    //_LOG("hpool: destroyed");
    doCleanup = false;
    clean();
    cleanup.join();
  }

  std::pair<curl_socket_t, bool> take(std::string host, curl_sockaddr *addr) {
    std::string hostkey = HostSocketFdPool::hostkey(host, &addr->addr);
    Lock lock(excl);

    if (pools.count(hostkey) == 0) {
      // create pool for new hostkey
      pools[hostkey] = std::make_shared<SocketFdPool>(max, hostkey);
    }

    std::pair<curl_socket_t, bool> item = pools[hostkey]->take(addr);
    curl_socket_t sockfd = item.first;
    taken[sockfd] = pools[hostkey];

    //_LOG("hpool: taken socket - " + stats());
    return item;
  }

  void putback(curl_socket_t sockfd) {
    Lock lock(excl);

    taken[sockfd]->putback(sockfd);
    taken.erase(sockfd);

    //_LOG("hpool: returned socket - " + stats());
  }

  bool clean() {
    Lock lock(excl);

    for (auto it = pools.begin(); it != pools.end(); /* nothing */) {
      auto pool = it->second;
      if (pool->clean()) {
        pools.erase(it++);
      } else {
        ++it;
      }
    }

    //_LOG("hpool: reset - " + stats());
    return (pools.size() + taken.size() == 0); // true when pool really is empty
  }

  std::string stats() {
    std::string stats;

    for (auto it = pools.begin(); it != pools.end(); ++it) {
      auto hostkey = it->first;
      auto pool = it->second;

      stats += hostkey + ": " + pool->stats() + "; ";
    }

    return stats;
  }

  std::map<std::string, std::map<std::string, int>> statsMap() {
    std::map<std::string, std::map<std::string, int>> stats;

    for (auto it = pools.begin(); it != pools.end(); ++it) {
      auto hostkey = it->first;
      auto pool = it->second;

      stats[hostkey] = pool->statsMap();
    }

    return stats;
  }

private:
  static std::string hostkey(std::string host, sockaddr *addr) {
    in_port_t port;
    //for ip: char ip[INET6_ADDRSTRLEN] = {0};

    switch (addr->sa_family) {
      case AF_INET: {
        sockaddr_in *sin = reinterpret_cast<sockaddr_in*>(addr);
        port = ntohs(sin->sin_port);
        //for ip: inet_ntop(AF_INET, &sin->sin_addr, ip, INET6_ADDRSTRLEN);
        break;
      }

      case AF_INET6: {
        sockaddr_in6 *sin = reinterpret_cast<sockaddr_in6*>(addr);
        port = ntohs(sin->sin6_port);
        //for ip: inet_ntop(AF_INET6, &sin->sin6_addr, ip, INET6_ADDRSTRLEN);
        break;
      }

      default:
        port = 0;
    }

    return host + ":" + std::to_string(port);
  };

  void periodicCleanup() {
    //_LOG("hpool: cleanup started"); // cannot log in a separate thread??
    do {
      std::this_thread::sleep_for(std::chrono::seconds(cleanupIntervalSec));
      //_LOG("hpool: cleaning up pool");
      clean();
      //_LOG("hpool: clean up - " + stats());
    } while (doCleanup);
    //_LOG("hpool: cleanup stopped");
  };
};

static std::shared_ptr<HostSocketFdPool> hostSocketFdPool;
/* CUSTOM_END */

///////////////////////////////////////////////////////////////////////////////
// helper data structure

class PCurlResource : public SweepableResourceData {
private:
  DECLARE_RESOURCE_ALLOCATION(PCurlResource)

  class WriteHandler {
  public:
    WriteHandler() : method(0), type(0) {}

    int                method;
    Variant            callback;
    req::ptr<File>     fp;
    StringBuffer       buf;
    String             content;
    int                type;
  };

  class ReadHandler {
  public:
    ReadHandler() : method(0) {}

    int                method;
    Variant            callback;
    req::ptr<File>     fp;
  };

  class ToFree {
  public:
    std::vector<char*>          str;
    std::vector<curl_httppost*> post;
    std::vector<curl_slist*>    slist;

    ~ToFree() {
      for (unsigned int i = 0; i < str.size(); i++) {
        free(str[i]);
      }
      for (unsigned int i = 0; i < post.size(); i++) {
        curl_formfree(post[i]);
      }
      for (unsigned int i = 0; i < slist.size(); i++) {
        curl_slist_free_all(slist[i]);
      }
    }
  };

public:
  CLASSNAME_IS("pcurl")
  // overriding ResourceData
  const String& o_getClassNameHook() const override { return classnameof(); }

  explicit PCurlResource(const String& url, PCurlHandlePool *pool = nullptr)
  : m_emptyPost(true), m_connPool(pool), m_pooledHandle(nullptr)
    /* CUSTOM_START */, m_oldSock(false) /* CUSTOM_END */ {
    if (m_connPool) {
      m_pooledHandle = m_connPool->fetch();
      m_cp = m_pooledHandle->useHandle();
    } else {
      m_cp = curl_easy_init();
    }
    m_url = url;

    memset(m_error_str, 0, sizeof(m_error_str));
    m_error_no = CURLE_OK;
    m_to_free = std::make_shared<ToFree>();

    m_write.method = PHP_CURL_STDOUT;
    m_write.type   = PHP_CURL_ASCII;
    m_read.method  = PHP_CURL_DIRECT;
    m_write_header.method = PHP_CURL_IGNORE;

    reset();

    if (!url.empty()) {
#if LIBCURL_VERSION_NUM >= 0x071100
      /* Strings passed to libcurl as 'char *' arguments, are copied by
         the library... NOTE: before 7.17.0 strings were not copied. */
      curl_easy_setopt(m_cp, CURLOPT_URL, url.c_str());
#else
      char *urlcopy = strndup(url.data(), url.size());
      curl_easy_setopt(m_cp, CURLOPT_URL, urlcopy);
      m_to_free->str.push_back(urlcopy);
#endif
    }
  }

  explicit PCurlResource(req::ptr<PCurlResource> src)
  : m_connPool(nullptr), m_pooledHandle(nullptr)/* CUSTOM_START */, m_oldSock(false) /* CUSTOM_END */ {
    // NOTE: we never pool copied curl handles, because all spots in
    // the pool are pre-populated

    assert(src && src != this);
    assert(!src->m_exception);

    m_cp = curl_easy_duphandle(src->get());
    m_url = src->m_url;

    memset(m_error_str, 0, sizeof(m_error_str));
    m_error_no = CURLE_OK;

    m_write.method = src->m_write.method;
    m_write.type   = src->m_write.type;
    m_read.method  = src->m_read.method;
    m_write_header.method = src->m_write_header.method;

    m_write.fp        = src->m_write.fp;
    m_write_header.fp = src->m_write_header.fp;
    m_read.fp         = src->m_read.fp;

    m_write.callback = src->m_write.callback;
    m_read.callback = src->m_read.callback;
    m_write_header.callback = src->m_write_header.callback;

    reseat();

    m_to_free = src->m_to_free;
    m_emptyPost = src->m_emptyPost;
  }

  ~PCurlResource() {
    close();
  }

  bool isInvalid() const override {
    return !m_cp;
  }

  void closeForSweep() {
    assert(!m_exception);
    if (m_cp) {
      if (m_connPool) {
        // reuse this curl handle if we're pooling
        assert(m_pooledHandle);
        m_connPool->store(m_pooledHandle);
        m_pooledHandle = nullptr;
      } else {
        curl_easy_cleanup(m_cp);
      }
      m_cp = nullptr;
    }
    m_to_free.reset();
  }

  void close() {
    closeForSweep();
    m_opts.clear();
  }

  void check_exception() {
    if (m_exception) {
      throwException(std::move(m_exception));
    }
  }

  ExceptionType getAndClearException() {
    return std::move(m_exception);
  }

  static int64_t minTimeout(int64_t timeout) {
    auto info = ThreadInfo::s_threadInfo.getNoCheck();
    auto& data = info->m_reqInjectionData;
    if (!data.getTimeout()) {
      return timeout;
    }
    auto remaining = int64_t(data.getRemainingTime());
    return std::min(remaining, timeout);
  }

  static int64_t minTimeoutMS(int64_t timeout) {
    auto info = ThreadInfo::s_threadInfo.getNoCheck();
    auto& data = info->m_reqInjectionData;
    if (!data.getTimeout()) {
      return timeout;
    }
    auto remaining = int64_t(data.getRemainingTime());
    return std::min(1000 * remaining, timeout);
  }

  void reseat() {
    // Note: this is the minimum set of things to point the CURL*
    // to this CurlHandle
    curl_easy_setopt(m_cp, CURLOPT_ERRORBUFFER,       m_error_str);
    curl_easy_setopt(m_cp, CURLOPT_FILE,              (void*)this);
    curl_easy_setopt(m_cp, CURLOPT_INFILE,            (void*)this);
    curl_easy_setopt(m_cp, CURLOPT_WRITEHEADER,       (void*)this);
    curl_easy_setopt(m_cp, CURLOPT_SSL_CTX_DATA,      (void*)this);

    /* CUSTOM_START */
    curl_easy_setopt(m_cp, CURLOPT_OPENSOCKETFUNCTION, opensocket_fn);
    curl_easy_setopt(m_cp, CURLOPT_OPENSOCKETDATA, (void *)this);
    curl_easy_setopt(m_cp, CURLOPT_SOCKOPTFUNCTION, sockopt_fn);
    curl_easy_setopt(m_cp, CURLOPT_SOCKOPTDATA, (void *)this);
    curl_easy_setopt(m_cp, CURLOPT_CLOSESOCKETFUNCTION, closesocket_fn);
    curl_easy_setopt(m_cp, CURLOPT_CLOSESOCKETDATA, (void *)this);
    /* CUSTOM_END */
  }

  void reset() {
    curl_easy_reset(m_cp);

    curl_easy_setopt(m_cp, CURLOPT_NOPROGRESS,        1);
    curl_easy_setopt(m_cp, CURLOPT_VERBOSE,           0);
    curl_easy_setopt(m_cp, CURLOPT_WRITEFUNCTION,     curl_write);
    curl_easy_setopt(m_cp, CURLOPT_READFUNCTION,      curl_read);
    curl_easy_setopt(m_cp, CURLOPT_HEADERFUNCTION,    curl_write_header);
    curl_easy_setopt(m_cp, CURLOPT_DNS_USE_GLOBAL_CACHE, 0); // for thread-safe
    curl_easy_setopt(m_cp, CURLOPT_DNS_CACHE_TIMEOUT, 120);
    curl_easy_setopt(m_cp, CURLOPT_MAXREDIRS, 20); // no infinite redirects
    curl_easy_setopt(m_cp, CURLOPT_NOSIGNAL, 1); // for multithreading mode
    curl_easy_setopt(m_cp, CURLOPT_SSL_CTX_FUNCTION,
                     PCurlResource::ssl_ctx_callback);

    curl_easy_setopt(m_cp, CURLOPT_TIMEOUT,
                     minTimeout(RuntimeOption::HttpDefaultTimeout));
    curl_easy_setopt(m_cp, CURLOPT_CONNECTTIMEOUT,
                     minTimeout(RuntimeOption::HttpDefaultTimeout));
    reseat();
  }

  Variant execute() {
    assert(!m_exception);
    if (m_cp == nullptr) {
      return false;
    }
    if (m_emptyPost) {
      // As per curl docs, an empty post must set POSTFIELDSIZE to be 0 or
      // the reader function will be called
      curl_easy_setopt(m_cp, CURLOPT_POSTFIELDSIZE, 0);
    }
    m_write.buf.clear();
    m_write.content.clear();
    m_header.clear();
    memset(m_error_str, 0, sizeof(m_error_str));

    {
      IOStatusHelper io("pcurl_easy_perform", m_url.data());
      SYNC_VM_REGS_SCOPED();
      m_error_no = curl_easy_perform(m_cp);
      check_exception();
    }
    set_curl_statuses(m_cp, m_url.data());

    /* CURLE_PARTIAL_FILE is returned by HEAD requests */
    if (m_error_no != CURLE_OK && m_error_no != CURLE_PARTIAL_FILE) {
      m_write.buf.clear();
      m_write.content.clear();
      return false;
    }

    if (m_write.method == PHP_CURL_RETURN) {
      if (!m_write.buf.empty()) {
        m_write.content = m_write.buf.detach();
      }
      if (!m_write.content.empty()) {
        return m_write.content;
      }
    }
    if (m_write.method == PHP_CURL_RETURN) {
      return empty_string_variant();
    }
    return true;
  }

  String getUrl() {
    return m_url;
  }

  String getHeader() {
    return m_header;
  }

  String getContents() {
    if (m_write.method == PHP_CURL_RETURN) {
      if (!m_write.buf.empty()) {
        m_write.content = m_write.buf.detach();
      }
      return m_write.content;
    }
    return String();
  }

  bool setOption(long option, const Variant& value) {
    if (m_cp == nullptr) {
      return false;
    }
    m_error_no = CURLE_OK;

    switch (option) {
    case CURLOPT_TIMEOUT: {
      auto timeout = minTimeout(value.toInt64());
      m_error_no = curl_easy_setopt(m_cp, (CURLoption)option, timeout);
      break;
    }
#if LIBCURL_VERSION_NUM >= 0x071002
    case CURLOPT_TIMEOUT_MS: {
      auto timeout = minTimeoutMS(value.toInt64());
      m_error_no = curl_easy_setopt(m_cp, (CURLoption)option, timeout);
      break;
    }
#endif
    case CURLOPT_INFILESIZE:
    case CURLOPT_VERBOSE:
    case CURLOPT_HEADER:
    case CURLOPT_NOPROGRESS:
    case CURLOPT_NOBODY:
    case CURLOPT_FAILONERROR:
    case CURLOPT_UPLOAD:
    case CURLOPT_POST:
#if LIBCURL_VERSION_NUM >= 0x071301
    case CURLOPT_POSTREDIR:
#endif
    case CURLOPT_PROTOCOLS:
    case CURLOPT_REDIR_PROTOCOLS:
    case CURLOPT_FTPLISTONLY:
    case CURLOPT_FTPAPPEND:
    case CURLOPT_NETRC:
    case CURLOPT_PUT:
    case CURLOPT_FTP_USE_EPSV:
    case CURLOPT_LOW_SPEED_LIMIT:
    case CURLOPT_SSLVERSION:
    case CURLOPT_LOW_SPEED_TIME:
    case CURLOPT_RESUME_FROM:
    case CURLOPT_TIMEVALUE:
    case CURLOPT_TIMECONDITION:
    case CURLOPT_TRANSFERTEXT:
    case CURLOPT_HTTPPROXYTUNNEL:
    case CURLOPT_FILETIME:
    case CURLOPT_MAXREDIRS:
    case CURLOPT_MAXCONNECTS:
    case CURLOPT_CLOSEPOLICY:
    case CURLOPT_FRESH_CONNECT:
    case CURLOPT_FORBID_REUSE:
    case CURLOPT_CONNECTTIMEOUT:
#if LIBCURL_VERSION_NUM >= 0x071002
    case CURLOPT_CONNECTTIMEOUT_MS:
#endif
    case CURLOPT_SSL_VERIFYHOST:
    case CURLOPT_SSL_VERIFYPEER:
      //case CURLOPT_DNS_USE_GLOBAL_CACHE: not thread-safe when set to true
    case CURLOPT_NOSIGNAL:
    case CURLOPT_PROXYTYPE:
    case CURLOPT_BUFFERSIZE:
    case CURLOPT_HTTPGET:
    case CURLOPT_HTTP_VERSION:
    case CURLOPT_CRLF:
    case CURLOPT_DNS_CACHE_TIMEOUT:
    case CURLOPT_PROXYPORT:
    case CURLOPT_FTP_USE_EPRT:
    case CURLOPT_HTTPAUTH:
    case CURLOPT_PROXYAUTH:
    case CURLOPT_FTP_CREATE_MISSING_DIRS:
    case CURLOPT_FTPSSLAUTH:
    case CURLOPT_FTP_SSL:
    case CURLOPT_UNRESTRICTED_AUTH:
    case CURLOPT_PORT:
    case CURLOPT_AUTOREFERER:
    case CURLOPT_COOKIESESSION:
    case CURLOPT_TCP_NODELAY:
    case CURLOPT_IPRESOLVE:
    case CURLOPT_FOLLOWLOCATION:
      m_error_no = curl_easy_setopt(m_cp, (CURLoption)option, value.toInt64());
      break;
    case CURLOPT_RETURNTRANSFER:
      m_write.method = value.toBoolean() ? PHP_CURL_RETURN : PHP_CURL_STDOUT;
      break;
    case CURLOPT_BINARYTRANSFER:
      m_write.type = value.toBoolean() ? PHP_CURL_BINARY : PHP_CURL_ASCII;
      break;
    case CURLOPT_PRIVATE:
    case CURLOPT_URL:
    case CURLOPT_PROXY:
    case CURLOPT_USERPWD:
    case CURLOPT_PROXYUSERPWD:
    case CURLOPT_RANGE:
    case CURLOPT_CUSTOMREQUEST:
    case CURLOPT_USERAGENT:
    case CURLOPT_FTPPORT:
    case CURLOPT_COOKIE:
    case CURLOPT_REFERER:
    case CURLOPT_INTERFACE:
    case CURLOPT_KRB4LEVEL:
    case CURLOPT_EGDSOCKET:
    case CURLOPT_CAINFO:
    case CURLOPT_CAPATH:
#ifdef FACEBOOK
    case CURLOPT_SERVICE_NAME:
#endif
    case CURLOPT_SSL_CIPHER_LIST:
    case CURLOPT_SSLKEY:
    case CURLOPT_SSLKEYTYPE:
    case CURLOPT_SSLKEYPASSWD:
    case CURLOPT_SSLENGINE:
    case CURLOPT_SSLENGINE_DEFAULT:
    case CURLOPT_SSLCERTTYPE:
    case CURLOPT_ENCODING:
    case CURLOPT_COOKIEJAR:
    case CURLOPT_SSLCERT:
    case CURLOPT_RANDOM_FILE:
    case CURLOPT_COOKIEFILE:
      {
        String svalue = value.toString();
#if LIBCURL_VERSION_NUM >= 0x071100
        /* Strings passed to libcurl as 'char *' arguments, are copied
           by the library... NOTE: before 7.17.0 strings were not copied. */
        m_error_no = curl_easy_setopt(m_cp, (CURLoption)option, svalue.c_str());
#else
        char *copystr = strndup(svalue.data(), svalue.size());
        m_to_free->str.push_back(copystr);
        m_error_no = curl_easy_setopt(m_cp, (CURLoption)option, copystr);
#endif
        if (option == CURLOPT_URL) m_url = value;
      }
      break;
    case CURLOPT_FILE:
    case CURLOPT_INFILE:
    case CURLOPT_WRITEHEADER:
    case CURLOPT_STDERR:
      {
        auto fp = dyn_cast_or_null<File>(value);
        if (!fp) return false;

        switch (option) {
          case CURLOPT_FILE:
            m_write.fp = fp;
            m_write.method = PHP_CURL_FILE;
            break;
          case CURLOPT_WRITEHEADER:
            m_write_header.fp = fp;
            m_write_header.method = PHP_CURL_FILE;
            break;
          case CURLOPT_INFILE:
            m_read.fp = fp;
            m_emptyPost = false;
            break;
          default: {
            auto pf = dyn_cast<PlainFile>(fp);
            if (!pf) {
              return false;
            }
            FILE *fp = pf->getStream();
            if (!fp) {
              return false;
            }
            m_error_no = curl_easy_setopt(m_cp, (CURLoption)option, fp);
            break;
          }
        }
      }
      break;
    case CURLOPT_WRITEFUNCTION:
      m_write.callback = value;
      m_write.method = PHP_CURL_USER;
      break;
    case CURLOPT_READFUNCTION:
      m_read.callback = value;
      m_read.method = PHP_CURL_USER;
      m_emptyPost = false;
      break;
    case CURLOPT_HEADERFUNCTION:
      m_write_header.callback = value;
      m_write_header.method = PHP_CURL_USER;
      break;
    case CURLOPT_PROGRESSFUNCTION:
      m_progress_callback = value;
      curl_easy_setopt(m_cp, CURLOPT_PROGRESSDATA, (void*) this);
      curl_easy_setopt(m_cp, CURLOPT_PROGRESSFUNCTION, curl_progress);
      break;
    case CURLOPT_POSTFIELDS:
      m_emptyPost = false;
      if (value.is(KindOfArray) || value.is(KindOfObject)) {
        Array arr = value.toArray();
        curl_httppost *first = nullptr;
        curl_httppost *last  = nullptr;
        for (ArrayIter iter(arr); iter; ++iter) {
          String key = iter.first().toString();
          Variant var_val = iter.second();
          if (UNLIKELY(var_val.isObject()
              && var_val.toObject()->instanceof(SystemLib::s_CURLFileClass))) {
            Object val = var_val.toObject();

            static const StaticString s_name("name");
            static const StaticString s_mime("mime");
            static const StaticString s_postname("postname");

            String name = val.o_get(s_name).toString();
            String mime = val.o_get(s_mime).toString();
            String postname = val.o_get(s_postname).toString();

            m_error_no = (CURLcode)curl_formadd
              (&first, &last,
               CURLFORM_COPYNAME, key.data(),
               CURLFORM_NAMELENGTH, (long)key.size(),
               CURLFORM_FILENAME, postname.empty()
                                  ? name.c_str()
                                  : postname.c_str(),
               CURLFORM_CONTENTTYPE, mime.empty()
                                     ? "application/octet-stream"
                                     : mime.c_str(),
               CURLFORM_FILE, name.c_str(),
               CURLFORM_END);
          } else {
            String val = var_val.toString();
            const char *postval = val.data();

            if (*postval == '@') {
              /* Given a string like:
               *   "@/foo/bar;type=herp/derp;filename=ponies\0"
               * - Temporarily convert to:
               *   "@/foo/bar\0type=herp/derp\0filename=ponies\0"
               * - Pass pointers to the relevant null-terminated substrings to
               *   curl_formadd
               * - Revert changes to postval at the end
               */
              char* mutablePostval = const_cast<char*>(postval) + 1;
              char* type = strstr(mutablePostval, ";type=");
              char* filename = strstr(mutablePostval, ";filename=");

              if (type) {
                *type = '\0';
              }
              if (filename) {
                *filename = '\0';
              }

              String localName = File::TranslatePath(mutablePostval);

              /* The arguments after _NAMELENGTH and _CONTENTSLENGTH
               * must be explicitly cast to long in curl_formadd
               * use since curl needs a long not an int. */
              m_error_no = (CURLcode)curl_formadd
                (&first, &last,
                 CURLFORM_COPYNAME, key.data(),
                 CURLFORM_NAMELENGTH, (long)key.size(),
                 CURLFORM_FILENAME, filename
                                    ? filename + sizeof(";filename=") - 1
                                    : postval,
                 CURLFORM_CONTENTTYPE, type
                                       ? type + sizeof(";type=") - 1
                                       : "application/octet-stream",
                 CURLFORM_FILE, localName.c_str(),
                 CURLFORM_END);

              if (type) {
                *type = ';';
              }
              if (filename) {
                *filename = ';';
              }
            } else {
              m_error_no = (CURLcode)curl_formadd
                (&first, &last,
                 CURLFORM_COPYNAME, key.data(),
                 CURLFORM_NAMELENGTH, (long)key.size(),
                 CURLFORM_COPYCONTENTS, postval,
                 CURLFORM_CONTENTSLENGTH,(long)val.size(),
                 CURLFORM_END);
            }
          }
        }

        if (m_error_no != CURLE_OK) {
          return false;
        }

        m_to_free->post.push_back(first);
        m_error_no = curl_easy_setopt(m_cp, CURLOPT_HTTPPOST, first);

      } else {
        String svalue = value.toString();
#if LIBCURL_VERSION_NUM >= 0x071100
        /* with curl 7.17.0 and later, we can use COPYPOSTFIELDS,
           but we have to provide size before */
        m_error_no = curl_easy_setopt(m_cp, CURLOPT_POSTFIELDSIZE,
                                      svalue.size());
        m_error_no = curl_easy_setopt(m_cp, CURLOPT_COPYPOSTFIELDS,
                                      svalue.c_str());
#else
        char *post = strndup(svalue.data(), svalue.size());
        m_to_free->str.push_back(post);

        m_error_no = curl_easy_setopt(m_cp, CURLOPT_POSTFIELDS, post);
        m_error_no = curl_easy_setopt(m_cp, CURLOPT_POSTFIELDSIZE,
                                      svalue.size());
#endif
      }
      break;
    case CURLOPT_HTTPHEADER:
    case CURLOPT_QUOTE:
    case CURLOPT_HTTP200ALIASES:
    case CURLOPT_POSTQUOTE:
    case CURLOPT_RESOLVE:
      if (value.is(KindOfArray) || value.is(KindOfObject)) {
        Array arr = value.toArray();
        curl_slist *slist = nullptr;
        for (ArrayIter iter(arr); iter; ++iter) {
          String key = iter.first().toString();
          String val = iter.second().toString();

          slist = curl_slist_append(slist, val.c_str());
          if (!slist) {
            raise_warning("Could not build curl_slist");
            return false;
          }
        }

        m_to_free->slist.push_back(slist);
        m_error_no = curl_easy_setopt(m_cp, (CURLoption)option, slist);

      } else {
        raise_warning("You must pass either an object or an array with "
                      "the CURLOPT_HTTPHEADER, CURLOPT_QUOTE, "
                      "CURLOPT_HTTP200ALIASES, CURLOPT_POSTQUOTE "
                      "and CURLOPT_RESOLVE arguments");
        return false;
      }
      break;

    case CURLINFO_HEADER_OUT:
      if (value.toInt64() == 1) {
        curl_easy_setopt(m_cp, CURLOPT_DEBUGFUNCTION, curl_debug);
        curl_easy_setopt(m_cp, CURLOPT_DEBUGDATA, (void *)this);
        curl_easy_setopt(m_cp, CURLOPT_VERBOSE, 1);
      } else {
        curl_easy_setopt(m_cp, CURLOPT_DEBUGFUNCTION, nullptr);
        curl_easy_setopt(m_cp, CURLOPT_DEBUGDATA, nullptr);
        curl_easy_setopt(m_cp, CURLOPT_VERBOSE, 0);
      }
      break;

    case CURLOPT_FB_TLS_VER_MAX:
      {
        int64_t val = value.toInt64();
        if (value.isInteger() &&
            (val == CURLOPT_FB_TLS_VER_MAX_1_0 ||
             val == CURLOPT_FB_TLS_VER_MAX_1_1 ||
             val == CURLOPT_FB_TLS_VER_MAX_NONE)) {
            m_opts.set(int64_t(option), value);
        } else {
          raise_warning("You must pass CURLOPT_FB_TLS_VER_MAX_1_0, "
                        "CURLOPT_FB_TLS_VER_MAX_1_1 or "
                        "CURLOPT_FB_TLS_VER_MAX_NONE with "
                        "CURLOPT_FB_TLS_VER_MAX");
        }
      }
      break;
    case CURLOPT_FB_TLS_CIPHER_SPEC:
      if (value.isString() && !value.toString().empty()) {
        m_opts.set(int64_t(option), value);
      } else {
        raise_warning("CURLOPT_FB_TLS_CIPHER_SPEC requires a non-empty string");
      }
      break;

    default:
      m_error_no = CURLE_FAILED_INIT;
      throw_invalid_argument("option: %ld", option);
      break;
    }

    m_opts.set(int64_t(option), value);

    return m_error_no == CURLE_OK;
  }

  Variant getOption(long option) {

    if (option != 0) {
      if (!m_opts.exists(int64_t(option))) {
        return false;
      }
      return m_opts[int64_t(option)];
    }

    return m_opts;
  }

  static int curl_debug(CURL *cp, curl_infotype type, char *buf,
                        size_t buf_len, void *ctx) {
    PCurlResource *ch = (PCurlResource *)ctx;
    if (type == CURLINFO_HEADER_OUT && buf_len > 0) {
      ch->m_header = String(buf, buf_len, CopyString);
    }
    return 0;
  }

  Variant do_callback(const Variant& cb, const Array& args) {
    assert(!m_exception);
    try {
      return vm_call_user_func(cb, args);
    } catch (const Object &e) {
      m_exception.assign(e);
    } catch (Exception &e) {
      m_exception.assign(e.clone());
    }
    return init_null();
  }

  /* CUSTOM_START */
  static curl_socket_t opensocket_fn(void *ctx, curlsocktype purpose,
                                     curl_sockaddr *addr) {
    //_LOG("curl callback: creating socket");

    PCurlResource *self = static_cast<PCurlResource *>(ctx);
    std::string url = self->m_url.toCppString();
    http::url parsedUrl = http::ParseHttpUrl(url);
    std::string hostn = parsedUrl.host;

    //auto _t = _starttime();
    std::pair<curl_socket_t, bool> item = hostSocketFdPool->take(hostn, addr);
    //_LOG("opensocket_fn - " + hostn + ": " + std::to_string(_stoptime(_t)));
    curl_socket_t sockfd = item.first;
    self->m_oldSock = item.second;

    return (sockfd == -1 ? CURL_SOCKET_BAD : sockfd);
  }

  static int sockopt_fn(void *ctx, curl_socket_t sockfd, curlsocktype purpose) {
    //_LOG("curl callback: setting socket options");

    PCurlResource *self = static_cast<PCurlResource *>(ctx);

    // check for freshly connected sockets
    if (!self->m_oldSock) {
      // keep-alive settings
      curl_easy_setopt(self->m_cp, CURLOPT_TCP_KEEPALIVE, 1L);
      curl_easy_setopt(self->m_cp, CURLOPT_TCP_KEEPIDLE, 10L);
      curl_easy_setopt(self->m_cp, CURLOPT_TCP_KEEPINTVL, 5L);

      return CURL_SOCKOPT_OK;
    }

    return CURL_SOCKOPT_ALREADY_CONNECTED;
  }

  static int closesocket_fn(void *ctx, curl_socket_t sockfd) {
    //_LOG("curl callback: closing socket");

    hostSocketFdPool->putback(sockfd);

    return CURL_SOCKOPT_OK;
  }
  /* CUSTOM_END */

  static int curl_progress(void* p,
                           double dltotal, double dlnow,
                           double ultotal, double ulnow) {
    assert(p);
    PCurlResource* curl = static_cast<PCurlResource*>(p);

    PackedArrayInit pai(5);
    pai.append(Resource(curl));
    pai.append(dltotal);
    pai.append(dlnow);
    pai.append(ultotal);
    pai.append(ulnow);

    Variant result = vm_call_user_func(
      curl->m_progress_callback,
      pai.toArray()
    );
    // Both PHP and libcurl are documented as return 0 to continue, non-zero
    // to abort, however this is what Zend actually implements
    return result.toInt64() == 0 ? 0 : 1;
  }

  static size_t curl_read(char *data, size_t size, size_t nmemb, void *ctx) {
    PCurlResource *ch = (PCurlResource *)ctx;
    ReadHandler *t  = &ch->m_read;

    int length = -1;
    switch (t->method) {
    case PHP_CURL_DIRECT:
      if (t->fp) {
        int data_size = size * nmemb;
        String ret = t->fp->read(data_size);
        length = ret.size();
        if (length) {
          memcpy(data, ret.data(), length);
        }
      }
      break;
    case PHP_CURL_USER:
      {
        int data_size = size * nmemb;
        Variant ret = ch->do_callback(
          t->callback,
          make_packed_array(Resource(ch), Resource(t->fp), data_size));
        if (ret.isString()) {
          String sret = ret.toString();
          length = data_size < sret.size() ? data_size : sret.size();
          memcpy(data, sret.data(), length);
        }
        break;
      }
    }
    return length;
  }

  static size_t curl_write(char *data, size_t size, size_t nmemb, void *ctx) {
    PCurlResource *ch = (PCurlResource *)ctx;
    WriteHandler *t  = &ch->m_write;
    size_t length = size * nmemb;

    switch (t->method) {
    case PHP_CURL_STDOUT:
      g_context->write(data, length);
      break;
    case PHP_CURL_FILE:
      return t->fp->write(String(data, length, CopyString), length);
    case PHP_CURL_RETURN:
      if (length > 0) {
        t->buf.append(data, (int)length);
      }
      break;
    case PHP_CURL_USER:
      {
        Variant ret = ch->do_callback(
          t->callback,
          make_packed_array(Resource(ch), String(data, length, CopyString)));
        length = ret.toInt64();
      }
      break;
    }

    return length;
  }

  static size_t curl_write_header(char *data, size_t size, size_t nmemb,
                                  void *ctx) {
    PCurlResource *ch = (PCurlResource *)ctx;
    WriteHandler *t  = &ch->m_write_header;
    size_t length = size * nmemb;

    switch (t->method) {
    case PHP_CURL_STDOUT:
      // Handle special case write when we're returning the entire transfer
      if (ch->m_write.method == PHP_CURL_RETURN && length > 0) {
        ch->m_write.buf.append(data, (int)length);
      } else {
        g_context->write(data, length);
      }
      break;
    case PHP_CURL_FILE:
      return t->fp->write(String(data, length, CopyString), length);
    case PHP_CURL_USER:
      {
        Variant ret = ch->do_callback(
          t->callback,
          make_packed_array(Resource(ch), String(data, length, CopyString)));
        length = ret.toInt64();
      }
      break;
    case PHP_CURL_IGNORE:
      return length;
    default:
      return (size_t)-1;
    }

    return length;
  }

  CURL *get(bool nullOkay = false) {
    if (m_cp == nullptr && !nullOkay) {
      throw_null_pointer_exception();
    }
    return m_cp;
  }

  int getError() {
    return m_error_no;
  }

  String getErrorString() {
    return String(m_error_str, CopyString);
  }

  typedef enum {
    CURLOPT_FB_TLS_VER_MAX = 2147482624,
    CURLOPT_FB_TLS_VER_MAX_NONE = 2147482625,
    CURLOPT_FB_TLS_VER_MAX_1_1 = 2147482626,
    CURLOPT_FB_TLS_VER_MAX_1_0 = 2147482627,
    CURLOPT_FB_TLS_CIPHER_SPEC = 2147482628
  } fb_specific_options;

private:
  CURL *m_cp;
  ExceptionType m_exception;

  char m_error_str[CURL_ERROR_SIZE + 1];
  CURLcode m_error_no;

  std::shared_ptr<ToFree> m_to_free;

  String m_url;
  String m_header;
  Array  m_opts;

  WriteHandler m_write;
  WriteHandler m_write_header;
  ReadHandler  m_read;
  Variant      m_progress_callback;

  bool m_emptyPost;
  PCurlHandlePool* m_connPool;
  PooledPCurlHandle* m_pooledHandle;

  /* CUSTOM_START */
  bool m_oldSock;
  /* CUSTOM_END */

  static CURLcode ssl_ctx_callback(CURL *curl, void *sslctx, void *parm);
};

void PCurlResource::sweep() {
  m_write.buf.release();
  m_write_header.buf.release();
  closeForSweep();
}

CURLcode PCurlResource::ssl_ctx_callback(CURL *curl, void *sslctx, void *parm) {
  // Set defaults from config.hdf
  CURLcode r = curl_tls_workarounds_cb(curl, sslctx, parm);
  if (r != CURLE_OK) {
    return r;
  }

  // Convert params to proper types.
  SSL_CTX* ctx = (SSL_CTX*)sslctx;
  if (ctx == nullptr) {
    raise_warning("supplied argument is not a valid SSL_CTX");
    return CURLE_FAILED_INIT;
  }
  PCurlResource* cp = (PCurlResource*)parm;
  if (cp == nullptr) {
    raise_warning("supplied argument is not a valid cURL handle resource");
    return CURLE_FAILED_INIT;
  }

  // Override cipher specs if necessary.
  if (cp->m_opts.exists(int64_t(CURLOPT_FB_TLS_CIPHER_SPEC))) {
    Variant untyped_value = cp->m_opts[int64_t(CURLOPT_FB_TLS_CIPHER_SPEC)];
    if (untyped_value.isString() && !untyped_value.toString().empty()) {
      SSL_CTX_set_cipher_list(ctx, untyped_value.toString().c_str());
    } else {
      raise_warning("CURLOPT_FB_TLS_CIPHER_SPEC requires a non-empty string");
    }
  }

  // Override the maximum client TLS version if necessary.
  if (cp->m_opts.exists(int64_t(CURLOPT_FB_TLS_VER_MAX))) {
    // Get current options, unsetting the NO_TLSv1_* bits.
    long cur_opts = SSL_CTX_get_options(ctx);
#ifdef SSL_OP_NO_TLSv1_1
    cur_opts &= ~SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
    cur_opts &= ~SSL_OP_NO_TLSv1_2;
#endif
    int64_t value = cp->m_opts[int64_t(CURLOPT_FB_TLS_VER_MAX)].toInt64();
    if (value == CURLOPT_FB_TLS_VER_MAX_1_0) {
#if defined (SSL_OP_NO_TLSv1_1) && defined (SSL_OP_NO_TLSv1_2)
      cur_opts |= SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
#else
      raise_notice("Requesting SSL_OP_NO_TLSv1_1, but this version of "
                   "SSL does not support that option");
#endif
    } else if (value == CURLOPT_FB_TLS_VER_MAX_1_1) {
#ifdef SSL_OP_NO_TLSv1_2
      cur_opts |= SSL_OP_NO_TLSv1_2;
#else
      raise_notice("Requesting SSL_OP_NO_TLSv1_2, but this version of "
                   "SSL does not support that option");
#endif
    } else if (value != CURLOPT_FB_TLS_VER_MAX_NONE) {
      raise_notice("Invalid CURLOPT_FB_TLS_VER_MAX value");
    }
    SSL_CTX_set_options(ctx, cur_opts);
  }

  return CURLE_OK;
}

///////////////////////////////////////////////////////////////////////////////

#define CHECK_RESOURCE(curl)                                                \
  auto curl = dyn_cast_or_null<PCurlResource>(ch);                           \
  if (curl == nullptr) {                                                    \
    raise_warning("supplied argument is not a valid cURL handle resource"); \
    return false;                                                           \
  }                                                                         \

#define CHECK_RESOURCE_RETURN_VOID(curl)                                    \
  auto curl = dyn_cast_or_null<PCurlResource>(ch);                           \
  if (curl == nullptr) {                                                    \
    raise_warning("supplied argument is not a valid cURL handle resource"); \
    return;                                                                 \
  }                                                                         \

Variant HHVM_FUNCTION(pcurl_init, const Variant& url /* = null_string */) {
  if (url.isNull()) {
    return Variant(req::make<PCurlResource>(null_string));
  } else {
    return Variant(req::make<PCurlResource>(url.toString()));
  }
}

Variant HHVM_FUNCTION(pcurl_init_pooled,
    const String& poolName,
    const Variant& url /* = null_string */)
{
  bool poolExists = (PCurlHandlePool::namedPools.find(poolName.toCppString()) !=
      PCurlHandlePool::namedPools.end());
  if (!poolExists) {
    raise_warning("Attempting to use connection pooling without "
                  "specifying an existent connection pool!");
  }
  PCurlHandlePool *pool = poolExists ?
    PCurlHandlePool::namedPools.at(poolName.toCppString()) : nullptr;

  return url.isNull() ? Variant(req::make<PCurlResource>(null_string, pool)) :
         Variant(req::make<PCurlResource>(url.toString(), pool));
}

Variant HHVM_FUNCTION(pcurl_copy_handle, const Resource& ch) {
  CHECK_RESOURCE(curl);
  return Variant(req::make<PCurlResource>(curl));
}

const StaticString
  s_version_number("version_number"),
  s_age("age"),
  s_features("features"),
  s_ssl_version_number("ssl_version_number"),
  s_version("version"),
  s_host("host"),
  s_ssl_version("ssl_version"),
  s_libz_version("libz_version"),
  s_protocols("protocols");

Variant HHVM_FUNCTION(pcurl_version, int uversion /* = k_PCURLVERSION_NOW */) {
  curl_version_info_data *d = curl_version_info((CURLversion)uversion);
  if (d == nullptr) {
    return false;
  }

  ArrayInit ret(9, ArrayInit::Map{});
  ret.set(s_version_number,     (int)d->version_num);
  ret.set(s_age,                d->age);
  ret.set(s_features,           d->features);
  ret.set(s_ssl_version_number, d->ssl_version_num);
  ret.set(s_version,            d->version);
  ret.set(s_host,               d->host);
  ret.set(s_ssl_version,        d->ssl_version);
  ret.set(s_libz_version,       d->libz_version);

  // Add an array of protocols
  char **p = (char **) d->protocols;
  Array protocol_list;
  while (*p != nullptr) {
    protocol_list.append(String(*p++, CopyString));
  }
  ret.set(s_protocols, protocol_list);
  return ret.toVariant();
}

bool HHVM_FUNCTION(pcurl_setopt, const Resource& ch, int option, const Variant& value) {
  CHECK_RESOURCE(curl);
  return curl->setOption(option, value);
}

bool HHVM_FUNCTION(pcurl_setopt_array, const Resource& ch, const Array& options) {
  CHECK_RESOURCE(curl);
  for (ArrayIter iter(options); iter; ++iter) {
    if (!curl->setOption(iter.first().toInt32(), iter.second())) {
      return false;
    }
  }
  return true;
}

Variant HHVM_FUNCTION(fb_pcurl_getopt, const Resource& ch, int64_t opt /* = 0 */) {
  CHECK_RESOURCE(curl);
  return curl->getOption(opt);
}

Variant HHVM_FUNCTION(pcurl_exec, const Resource& ch) {
  CHECK_RESOURCE(curl);
  return curl->execute();
}

const StaticString
  s_url("url"),
  s_content_type("content_type"),
  s_http_code("http_code"),
  s_header_size("header_size"),
  s_request_size("request_size"),
  s_filetime("filetime"),
  s_ssl_verify_result("ssl_verify_result"),
  s_redirect_count("redirect_count"),
  s_local_port("local_port"),
  s_total_time("total_time"),
  s_namelookup_time("namelookup_time"),
  s_connect_time("connect_time"),
  s_pretransfer_time("pretransfer_time"),
  s_size_upload("size_upload"),
  s_size_download("size_download"),
  s_speed_download("speed_download"),
  s_speed_upload("speed_upload"),
  s_download_content_length("download_content_length"),
  s_upload_content_length("upload_content_length"),
  s_starttransfer_time("starttransfer_time"),
  s_redirect_time("redirect_time"),
  s_request_header("request_header");

Variant HHVM_FUNCTION(pcurl_getinfo, const Resource& ch, int opt /* = 0 */) {
  CHECK_RESOURCE(curl);
  CURL *cp = curl->get();

  if (opt == 0) {
    char   *s_code;
    long    l_code;
    double  d_code;

    Array ret;
    if (curl_easy_getinfo(cp, CURLINFO_EFFECTIVE_URL, &s_code) == CURLE_OK) {
      ret.set(s_url, String(s_code, CopyString));
    }
    if (curl_easy_getinfo(cp, CURLINFO_CONTENT_TYPE, &s_code) == CURLE_OK) {
      if (s_code != nullptr) {
        ret.set(s_content_type, String(s_code, CopyString));
      } else {
        ret.set(s_content_type, init_null());
      }
    }
    if (curl_easy_getinfo(cp, CURLINFO_HTTP_CODE, &l_code) == CURLE_OK) {
      ret.set(s_http_code, l_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_HEADER_SIZE, &l_code) == CURLE_OK) {
      ret.set(s_header_size, l_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_REQUEST_SIZE, &l_code) == CURLE_OK) {
      ret.set(s_request_size, l_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_FILETIME, &l_code) == CURLE_OK) {
      ret.set(s_filetime, l_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_SSL_VERIFYRESULT, &l_code) ==
        CURLE_OK) {
      ret.set(s_ssl_verify_result, l_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_REDIRECT_COUNT, &l_code) == CURLE_OK) {
      ret.set(s_redirect_count, l_code);
    }
#if LIBCURL_VERSION_NUM >= 0x071500
    if (curl_easy_getinfo(cp, CURLINFO_LOCAL_PORT, &l_code) == CURLE_OK) {
      ret.set(s_local_port, l_code);
    }
#endif
    if (curl_easy_getinfo(cp, CURLINFO_TOTAL_TIME, &d_code) == CURLE_OK) {
      ret.set(s_total_time, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_NAMELOOKUP_TIME, &d_code) == CURLE_OK) {
      ret.set(s_namelookup_time, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_CONNECT_TIME, &d_code) == CURLE_OK) {
      ret.set(s_connect_time, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_PRETRANSFER_TIME, &d_code) ==
        CURLE_OK) {
      ret.set(s_pretransfer_time, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_SIZE_UPLOAD, &d_code) == CURLE_OK) {
      ret.set(s_size_upload, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_SIZE_DOWNLOAD, &d_code) == CURLE_OK) {
      ret.set(s_size_download, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_SPEED_DOWNLOAD, &d_code) == CURLE_OK) {
      ret.set(s_speed_download, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_SPEED_UPLOAD, &d_code) == CURLE_OK) {
      ret.set(s_speed_upload, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &d_code) ==
        CURLE_OK) {
      ret.set(s_download_content_length, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_CONTENT_LENGTH_UPLOAD, &d_code) ==
        CURLE_OK) {
      ret.set(s_upload_content_length, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_STARTTRANSFER_TIME, &d_code) ==
        CURLE_OK) {
      ret.set(s_starttransfer_time, d_code);
    }
    if (curl_easy_getinfo(cp, CURLINFO_REDIRECT_TIME, &d_code) == CURLE_OK) {
      ret.set(s_redirect_time, d_code);
    }
    String header = curl->getHeader();
    if (!header.empty()) {
      ret.set(s_request_header, header);
    }
    return ret;
  }

  switch (opt) {
  case CURLINFO_PRIVATE:
  case CURLINFO_EFFECTIVE_URL:
  case CURLINFO_CONTENT_TYPE: {
    char *s_code = nullptr;
    if (curl_easy_getinfo(cp, (CURLINFO)opt, &s_code) == CURLE_OK &&
        s_code) {
      return String(s_code, CopyString);
    }
    return false;
  }
  case CURLINFO_HTTP_CODE:
  case CURLINFO_HEADER_SIZE:
  case CURLINFO_REQUEST_SIZE:
  case CURLINFO_FILETIME:
  case CURLINFO_SSL_VERIFYRESULT:
#if LIBCURL_VERSION_NUM >= 0x071500
  case CURLINFO_LOCAL_PORT:
#endif
  case CURLINFO_REDIRECT_COUNT: {
    long code = 0;
    if (curl_easy_getinfo(cp, (CURLINFO)opt, &code) == CURLE_OK) {
      return code;
    }
    return false;
  }
  case CURLINFO_TOTAL_TIME:
  case CURLINFO_NAMELOOKUP_TIME:
  case CURLINFO_CONNECT_TIME:
  case CURLINFO_PRETRANSFER_TIME:
  case CURLINFO_SIZE_UPLOAD:
  case CURLINFO_SIZE_DOWNLOAD:
  case CURLINFO_SPEED_DOWNLOAD:
  case CURLINFO_SPEED_UPLOAD:
  case CURLINFO_CONTENT_LENGTH_DOWNLOAD:
  case CURLINFO_CONTENT_LENGTH_UPLOAD:
  case CURLINFO_STARTTRANSFER_TIME:
  case CURLINFO_REDIRECT_TIME: {
    double code = 0.0;
    if (curl_easy_getinfo(cp, (CURLINFO)opt, &code) == CURLE_OK) {
      return code;
    }
    return false;
  }
  case CURLINFO_HEADER_OUT:
    {
      String header = curl->getHeader();
      if (!header.empty()) {
        return header;
      }
      return false;
    }
  }

  return init_null();
}

Variant HHVM_FUNCTION(pcurl_errno, const Resource& ch) {
  CHECK_RESOURCE(curl);
  return curl->getError();
}

Variant HHVM_FUNCTION(pcurl_error, const Resource& ch) {
  CHECK_RESOURCE(curl);
  return curl->getErrorString();
}

String HHVM_FUNCTION(pcurl_strerror, int code) {
  return curl_easy_strerror((CURLcode)code);
}

Variant HHVM_FUNCTION(pcurl_close, const Resource& ch) {
  CHECK_RESOURCE(curl);
  curl->close();
  return init_null();
}

void HHVM_FUNCTION(pcurl_reset, const Resource& ch) {
  CHECK_RESOURCE_RETURN_VOID(curl);
  curl->reset();
}

///////////////////////////////////////////////////////////////////////////////

class PCurlMultiResource : public SweepableResourceData {
public:
  DECLARE_RESOURCE_ALLOCATION(PCurlMultiResource)

  CLASSNAME_IS("pcurl_multi")
  // overriding ResourceData
  const String& o_getClassNameHook() const override { return classnameof(); }

  PCurlMultiResource() {
    m_multi = curl_multi_init();
  }

  ~PCurlMultiResource() {
    close();
  }

  void close() {
    if (m_multi) {
      curl_multi_cleanup(m_multi);
      m_easyh.clear();
      m_multi = nullptr;
    }
  }

  bool isInvalid() const override {
    return !m_multi;
  }

  void add(const Resource& ch) {
    m_easyh.append(ch);
  }

  void remove(req::ptr<PCurlResource> curle) {
    for (ArrayIter iter(m_easyh); iter; ++iter) {
      if (cast<PCurlResource>(iter.second())->get(true) ==
          curle->get()) {
        m_easyh.remove(iter.first());
        return;
      }
    }
  }

  Resource find(CURL *cp) {
    for (ArrayIter iter(m_easyh); iter; ++iter) {
      if (cast<PCurlResource>(iter.second())->get(true) == cp) {
        return iter.second().toResource();
      }
    }
    return Resource();
  }

  void check_exceptions() {
    ExceptionType ex;
    Object lastPhpException;
    for (ArrayIter iter(m_easyh); iter; ++iter) {
      auto curl = cast<PCurlResource>(iter.second());
      ExceptionType nextException(curl->getAndClearException());
      if (isPhpException(nextException)) {
        Object phpException(getPhpException(nextException));
        phpException->o_set(s_previous, lastPhpException, s_exception);
        lastPhpException = std::move(phpException);
      }
      ex = std::move(nextException);
    }
    if (ex) {
      throwException(std::move(ex));
    }
  }

  CURLM *get() {
    if (m_multi == nullptr) {
      throw_null_pointer_exception();
    }
    return m_multi;
  }

  const Array& getEasyHandles() const {
    return m_easyh;
  }

private:
  CURLM *m_multi;
  Array m_easyh;
};

void PCurlMultiResource::sweep() {
  if (m_multi) {
    curl_multi_cleanup(m_multi);
  }
}

///////////////////////////////////////////////////////////////////////////////

#define CURLM_ARG_WARNING "expects parameter 1 to be cURL multi resource"

#define CHECK_MULTI_RESOURCE(curlm)                                      \
  auto curlm = dyn_cast_or_null<PCurlMultiResource>(mh);                 \
  if (!curlm || curlm->isInvalid()) {                                    \
    raise_warning(CURLM_ARG_WARNING);                                    \
    return init_null();                                                  \
  }

#define CHECK_MULTI_RESOURCE_RETURN_VOID(curlm) \
  auto curlm = dyn_cast_or_null<PCurlMultiResource>(mh);                 \
  if (!curlm || curlm->isInvalid()) {                                    \
    raise_warning(CURLM_ARG_WARNING);                                    \
    return;                                                              \
  }

#define CHECK_MULTI_RESOURCE_THROW(curlm)                               \
  auto curlm = dyn_cast_or_null<PCurlMultiResource>(mh);                \
  if (!curlm || curlm->isInvalid()) {                                   \
    SystemLib::throwExceptionObject(CURLM_ARG_WARNING);                 \
  }

/* CUSTOM_START */
String HHVM_FUNCTION(pcurl_pool_stats) {
  return String("sockets: " + hostSocketFdPool->stats());
}

Array HHVM_FUNCTION(pcurl_pool_stats_array) {
  Array ret = Array::Create();

  auto stats = hostSocketFdPool->statsMap();
  for (auto hostIt = stats.begin(); hostIt != stats.end(); ++hostIt) {
    auto hostkey = hostIt->first;
    auto pool = hostIt->second;

    Array retSingle = Array::Create();
    for (auto it = pool.begin(); it != pool.end(); ++it) {
      auto state = it->first;
      auto count = it->second;

      retSingle.set(String(state), count);
    }

    ret.set(String(hostkey), retSingle);
  }

  return ret;
}

bool HHVM_FUNCTION(pcurl_pool_reset) {
  return hostSocketFdPool->clean();
}
/* CUSTOM_END*/

Resource HHVM_FUNCTION(pcurl_multi_init) {
  return Resource(req::make<PCurlMultiResource>());
}

Variant HHVM_FUNCTION(pcurl_multi_add_handle, const Resource& mh, const Resource& ch) {
  CHECK_MULTI_RESOURCE(curlm);
  auto curle = cast<PCurlResource>(ch);
  curlm->add(ch);
  return curl_multi_add_handle(curlm->get(), curle->get());
}

Variant HHVM_FUNCTION(pcurl_multi_remove_handle, const Resource& mh, const Resource& ch) {
  CHECK_MULTI_RESOURCE(curlm);
  auto curle = cast<PCurlResource>(ch);
  curlm->remove(curle);
  return curl_multi_remove_handle(curlm->get(), curle->get());
}

Variant HHVM_FUNCTION(pcurl_multi_exec, const Resource& mh, VRefParam still_running) {
  CHECK_MULTI_RESOURCE(curlm);
  int running = 0;
  IOStatusHelper io("pcurl_multi_exec");
  SYNC_VM_REGS_SCOPED();
  int result = curl_multi_perform(curlm->get(), &running);
  curlm->check_exceptions();
  still_running.assignIfRef(running);
  return result;
}

/* Fallback implementation of curl_multi_select()
 *
 * This allows the OSS build to work with older package
 * versions of libcurl, but will fail with file descriptors
 * over 1024.
 */
UNUSED
static void hphp_curl_multi_select(CURLM *mh, int timeout_ms, int *ret) {
  fd_set read_fds, write_fds, except_fds;
  int maxfds, nfds = -1;
  struct timeval tv;

  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_ZERO(&except_fds);

  tv.tv_sec  =  timeout_ms / 1000;
  tv.tv_usec = (timeout_ms * 1000) % 1000000;

  curl_multi_fdset(mh, &read_fds, &write_fds, &except_fds, &maxfds);
  if (maxfds < 1024) {
    nfds = select(maxfds + 1, &read_fds, &write_fds, &except_fds, &tv);
  } else {
    /* fd_set can only hold sockets from 0 to 1023,
     * anything higher is ignored by FD_SET()
     * avoid "unexplained" behavior by failing outright
     */
    raise_warning("libcurl versions < 7.28.0 do not support selecting on "
                  "file descriptors of 1024 or higher.");
  }
  if (ret) {
    *ret = nfds;
  }
}

#ifndef HAVE_CURL_MULTI_SELECT
# ifdef HAVE_CURL_MULTI_WAIT
#  define curl_multi_select_func(mh, tm, ret) curl_multi_wait((mh), nullptr, 0, (tm), (ret))
# else
#  define curl_multi_select_func hphp_curl_multi_select
# endif
#else
#define curl_multi_select_func(mh, tm, ret) curl_multi_wait((mh), nullptr, 0, (tm), (ret))
#endif

Variant HHVM_FUNCTION(pcurl_multi_select, const Resource& mh,
                                         double timeout /* = 1.0 */) {
  CHECK_MULTI_RESOURCE(curlm);
  int ret;
  unsigned long timeout_ms = (unsigned long)(timeout * 1000.0);
  IOStatusHelper io("pcurl_multi_select");
  curl_multi_select_func(curlm->get(), timeout_ms, &ret);
  return ret;
}

class PCurlMultiAwait;

class PCurlEventHandler : public AsioEventHandler {
 public:
  PCurlEventHandler(AsioEventBase* base, int fd, PCurlMultiAwait* cma):
    AsioEventHandler(base, fd), m_curlMultiAwait(cma), m_fd(fd) {}

  void handlerReady(uint16_t events) noexcept override;
 private:
  PCurlMultiAwait* m_curlMultiAwait;
  int m_fd;
};

class PCurlTimeoutHandler : public AsioTimeoutHandler {
 public:
  PCurlTimeoutHandler(AsioEventBase* base, PCurlMultiAwait* cma):
    AsioTimeoutHandler(base), m_curlMultiAwait(cma) {}

  void timeoutExpired() noexcept override;
 private:
  PCurlMultiAwait* m_curlMultiAwait;
};

class PCurlMultiAwait : public AsioExternalThreadEvent {
 public:
  PCurlMultiAwait(req::ptr<PCurlMultiResource> multi, double timeout) {
    if ((addLowHandles(multi) + addHighHandles(multi)) == 0) {
      // Nothing to do
      markAsFinished();
      return;
    }

    // Add optional timeout
    int64_t timeout_ms = timeout * 1000;
    if (timeout_ms > 0) {
      m_timeout = std::shared_ptr<PCurlTimeoutHandler>
        (new PCurlTimeoutHandler(s_asio_event_base.get(), this));
      s_asio_event_base->runInEventBaseThread([this, timeout_ms]{
        m_timeout->scheduleTimeout(timeout_ms);
      });
    }
  }

  ~PCurlMultiAwait() {
    for (auto handler : m_handlers) {
      handler->unregisterHandler();
    }
    if (m_timeout) {
      std::shared_ptr<PCurlTimeoutHandler> to = m_timeout;
      s_asio_event_base->runInEventBaseThreadAndWait([to]{
        to.get()->cancelTimeout();
      });
      m_timeout.reset();
    }
    m_handlers.clear();
  }

  void unserialize(Cell& c) {
    c.m_type = KindOfInt64;
    c.m_data.num = m_result;
  }

  void setFinished(int fd) {
    if (m_result < fd) {
      m_result = fd;
    }
    if (!m_finished) {
      markAsFinished();
      m_finished = true;
    }
  }

 private:
  void addHandle(int fd, int events) {
    auto handler =
      std::make_shared<PCurlEventHandler>(s_asio_event_base.get(), fd, this);
    handler->registerHandler(events);
    m_handlers.push_back(handler);
  }

  // Ask curl_multi for its handles directly
  // This is preferable as we get to know which
  // are blocking on reads, and which on writes.
  int addLowHandles(req::ptr<PCurlMultiResource> multi) {
    fd_set read_fds, write_fds;
    int max_fd = -1, count = 0;
    FD_ZERO(&read_fds); FD_ZERO(&write_fds);
    if ((CURLM_OK != curl_multi_fdset(multi->get(), &read_fds, &write_fds,
                                      nullptr, &max_fd)) ||
        (max_fd < 0)) {
      return count;
    }
    for (int i = 0 ; i <= max_fd; ++i) {
      int events = 0;
      if (FD_ISSET(i, &read_fds))  events |= AsioEventHandler::READ;
      if (FD_ISSET(i, &write_fds)) events |= AsioEventHandler::WRITE;
      if (events) {
        addHandle(i, events);
        ++count;
      }
    }
    return count;
  }

  // Check for file descriptors >= FD_SETSIZE
  // which can't be returned in an fdset
  // This is a little hacky, but necessary given cURL's APIs
  int addHighHandles(req::ptr<PCurlMultiResource> multi) {
    int count = 0;
    auto easy_handles = multi->getEasyHandles();
    for (ArrayIter iter(easy_handles); iter; ++iter) {
      Variant easy_handle = iter.second();
      auto easy = dyn_cast_or_null<PCurlResource>(easy_handle);
      if (!easy) continue;
      long sock;
      if ((curl_easy_getinfo(easy->get(),
                             CURLINFO_LASTSOCKET, &sock) != CURLE_OK) ||
          (sock < FD_SETSIZE)) {
        continue;
      }
      // No idea which type of event it needs, ask for everything
      addHandle(sock, AsioEventHandler::READ_WRITE);
      ++count;
    }
    return count;
  }

  std::shared_ptr<PCurlTimeoutHandler> m_timeout;
  std::vector<std::shared_ptr<PCurlEventHandler>> m_handlers;
  int m_result{-1};
  bool m_finished{false};
};

void PCurlEventHandler::handlerReady(uint16_t events) noexcept {
  m_curlMultiAwait->setFinished(m_fd);
}

void PCurlTimeoutHandler::timeoutExpired() noexcept {
  m_curlMultiAwait->setFinished(-1);
}

Object HHVM_FUNCTION(pcurl_multi_await, const Resource& mh,
                                       double timeout /*=1.0*/) {
  CHECK_MULTI_RESOURCE_THROW(curlm);
  auto ev = new PCurlMultiAwait(curlm, timeout);
  try {
    return Object{ev->getWaitHandle()};
  } catch (...) {
    assert(false);
    ev->abandon();
    throw;
  }
}

Variant HHVM_FUNCTION(pcurl_multi_getcontent, const Resource& ch) {
  CHECK_RESOURCE(curl);
  return curl->getContents();
}

Array curl_convert_fd_to_stream(fd_set *fd, int max_fd) {
  Array ret = Array::Create();
  for (int i=0; i<=max_fd; i++) {
    if (FD_ISSET(i, fd)) {
      ret.append(Variant(req::make<BuiltinFile>(i)));
    }
  }
  return ret;
}

Variant HHVM_FUNCTION(fb_pcurl_multi_fdset, const Resource& mh,
                      VRefParam read_fd_set,
                      VRefParam write_fd_set,
                      VRefParam exc_fd_set,
                      VRefParam max_fd /* = null_object */) {
  CHECK_MULTI_RESOURCE(curlm);

  fd_set read_set;
  fd_set write_set;
  fd_set exc_set;
  int max = 0;

  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  FD_ZERO(&exc_set);

  int r = curl_multi_fdset(curlm->get(), &read_set, &write_set, &exc_set, &max);
  read_fd_set.assignIfRef(curl_convert_fd_to_stream(&read_set, max));
  write_fd_set.assignIfRef(curl_convert_fd_to_stream(&write_set, max));
  exc_fd_set.assignIfRef(curl_convert_fd_to_stream(&exc_set, max));
  max_fd.assignIfRef(max);

  return r;
}

const StaticString
  s_msg("msg"),
  s_result("result"),
  s_handle("handle");

Variant HHVM_FUNCTION(pcurl_multi_info_read, const Resource& mh,
                      VRefParam msgs_in_queue /* = null */) {
  CHECK_MULTI_RESOURCE(curlm);

  int queued_msgs;
  CURLMsg *tmp_msg = curl_multi_info_read(curlm->get(), &queued_msgs);
  curlm->check_exceptions();
  if (tmp_msg == nullptr) {
    return false;
  }
  msgs_in_queue.assignIfRef(queued_msgs);

  Array ret;
  ret.set(s_msg, tmp_msg->msg);
  ret.set(s_result, tmp_msg->data.result);
  Resource curle = curlm->find(tmp_msg->easy_handle);
  if (!curle.isNull()) {
    ret.set(s_handle, curle);
  }
  return ret;
}

Variant HHVM_FUNCTION(pcurl_multi_close, const Resource& mh) {
  CHECK_MULTI_RESOURCE(curlm);
  curlm->close();
  return init_null();
}

///////////////////////////////////////////////////////////////////////////////

#if LIBCURL_VERSION_NUM >= 0x071500
const int64_t k_PCURLINFO_LOCAL_PORT = CURLINFO_LOCAL_PORT;
#endif

#if LIBCURL_VERSION_NUM >= 0x071002
const int64_t k_PCURLOPT_TIMEOUT_MS = CURLOPT_TIMEOUT_MS;
const int64_t k_PCURLOPT_CONNECTTIMEOUT_MS = CURLOPT_CONNECTTIMEOUT_MS;
#endif

const int64_t k_PCURLAUTH_ANY = CURLAUTH_ANY;
const int64_t k_PCURLAUTH_ANYSAFE = CURLAUTH_ANYSAFE;
const int64_t k_PCURLAUTH_BASIC = CURLAUTH_BASIC;
const int64_t k_PCURLAUTH_DIGEST = CURLAUTH_DIGEST;
const int64_t k_PCURLAUTH_GSSNEGOTIATE = CURLAUTH_GSSNEGOTIATE;
const int64_t k_PCURLAUTH_NTLM = CURLAUTH_NTLM;
const int64_t k_PCURLCLOSEPOLICY_CALLBACK = CURLCLOSEPOLICY_CALLBACK;
const int64_t k_PCURLCLOSEPOLICY_LEAST_RECENTLY_USED =
  CURLCLOSEPOLICY_LEAST_RECENTLY_USED;
const int64_t k_PCURLCLOSEPOLICY_LEAST_TRAFFIC = CURLCLOSEPOLICY_LEAST_TRAFFIC;
const int64_t k_PCURLCLOSEPOLICY_OLDEST = CURLCLOSEPOLICY_OLDEST;
const int64_t k_PCURLCLOSEPOLICY_SLOWEST = CURLCLOSEPOLICY_SLOWEST;
const int64_t k_PCURLE_ABORTED_BY_CALLBACK = CURLE_ABORTED_BY_CALLBACK;
const int64_t k_PCURLE_BAD_CALLING_ORDER = CURLE_BAD_CALLING_ORDER;
const int64_t k_PCURLE_BAD_CONTENT_ENCODING = CURLE_BAD_CONTENT_ENCODING;
const int64_t k_PCURLE_BAD_FUNCTION_ARGUMENT = CURLE_BAD_FUNCTION_ARGUMENT;
const int64_t k_PCURLE_BAD_PASSWORD_ENTERED = CURLE_BAD_PASSWORD_ENTERED;
const int64_t k_PCURLE_COULDNT_CONNECT = CURLE_COULDNT_CONNECT;
const int64_t k_PCURLE_COULDNT_RESOLVE_HOST = CURLE_COULDNT_RESOLVE_HOST;
const int64_t k_PCURLE_COULDNT_RESOLVE_PROXY = CURLE_COULDNT_RESOLVE_PROXY;
const int64_t k_PCURLE_FAILED_INIT = CURLE_FAILED_INIT;
const int64_t k_PCURLE_FILESIZE_EXCEEDED = CURLE_FILESIZE_EXCEEDED;
const int64_t k_PCURLE_FILE_COULDNT_READ_FILE = CURLE_FILE_COULDNT_READ_FILE;
const int64_t k_PCURLE_FTP_ACCESS_DENIED = CURLE_FTP_ACCESS_DENIED;
const int64_t k_PCURLE_FTP_BAD_DOWNLOAD_RESUME = CURLE_FTP_BAD_DOWNLOAD_RESUME;
const int64_t k_PCURLE_FTP_CANT_GET_HOST = CURLE_FTP_CANT_GET_HOST;
const int64_t k_PCURLE_FTP_CANT_RECONNECT = CURLE_FTP_CANT_RECONNECT;
const int64_t k_PCURLE_FTP_COULDNT_GET_SIZE = CURLE_FTP_COULDNT_GET_SIZE;
const int64_t k_PCURLE_FTP_COULDNT_RETR_FILE = CURLE_FTP_COULDNT_RETR_FILE;
const int64_t k_PCURLE_FTP_COULDNT_SET_ASCII = CURLE_FTP_COULDNT_SET_ASCII;
const int64_t k_PCURLE_FTP_COULDNT_SET_BINARY = CURLE_FTP_COULDNT_SET_BINARY;
const int64_t k_PCURLE_FTP_COULDNT_STOR_FILE = CURLE_FTP_COULDNT_STOR_FILE;
const int64_t k_PCURLE_FTP_COULDNT_USE_REST = CURLE_FTP_COULDNT_USE_REST;
const int64_t k_PCURLE_FTP_PORT_FAILED = CURLE_FTP_PORT_FAILED;
const int64_t k_PCURLE_FTP_QUOTE_ERROR = CURLE_FTP_QUOTE_ERROR;
const int64_t k_PCURLE_FTP_SSL_FAILED = CURLE_FTP_SSL_FAILED;
const int64_t k_PCURLE_FTP_USER_PASSWORD_INCORRECT =
  CURLE_FTP_USER_PASSWORD_INCORRECT;
const int64_t k_PCURLE_FTP_WEIRD_227_FORMAT = CURLE_FTP_WEIRD_227_FORMAT;
const int64_t k_PCURLE_FTP_WEIRD_PASS_REPLY = CURLE_FTP_WEIRD_PASS_REPLY;
const int64_t k_PCURLE_FTP_WEIRD_PASV_REPLY = CURLE_FTP_WEIRD_PASV_REPLY;
const int64_t k_PCURLE_FTP_WEIRD_SERVER_REPLY = CURLE_FTP_WEIRD_SERVER_REPLY;
const int64_t k_PCURLE_FTP_WEIRD_USER_REPLY = CURLE_FTP_WEIRD_USER_REPLY;
const int64_t k_PCURLE_FTP_WRITE_ERROR = CURLE_FTP_WRITE_ERROR;
const int64_t k_PCURLE_FUNCTION_NOT_FOUND = CURLE_FUNCTION_NOT_FOUND;
const int64_t k_PCURLE_GOT_NOTHING = CURLE_GOT_NOTHING;
const int64_t k_PCURLE_HTTP_NOT_FOUND = CURLE_HTTP_NOT_FOUND;
const int64_t k_PCURLE_HTTP_PORT_FAILED = CURLE_HTTP_PORT_FAILED;
const int64_t k_PCURLE_HTTP_POST_ERROR = CURLE_HTTP_POST_ERROR;
const int64_t k_PCURLE_HTTP_RANGE_ERROR = CURLE_HTTP_RANGE_ERROR;
const int64_t k_PCURLE_LDAP_CANNOT_BIND = CURLE_LDAP_CANNOT_BIND;
const int64_t k_PCURLE_LDAP_INVALID_URL = CURLE_LDAP_INVALID_URL;
const int64_t k_PCURLE_LDAP_SEARCH_FAILED = CURLE_LDAP_SEARCH_FAILED;
const int64_t k_PCURLE_LIBRARY_NOT_FOUND = CURLE_LIBRARY_NOT_FOUND;
const int64_t k_PCURLE_MALFORMAT_USER = CURLE_MALFORMAT_USER;
const int64_t k_PCURLE_OBSOLETE = CURLE_OBSOLETE;
const int64_t k_PCURLE_OK = CURLE_OK;
const int64_t k_PCURLE_OPERATION_TIMEOUTED = CURLE_OPERATION_TIMEOUTED;
const int64_t k_PCURLE_OUT_OF_MEMORY = CURLE_OUT_OF_MEMORY;
const int64_t k_PCURLE_PARTIAL_FILE = CURLE_PARTIAL_FILE;
const int64_t k_PCURLE_READ_ERROR = CURLE_READ_ERROR;
const int64_t k_PCURLE_RECV_ERROR = CURLE_RECV_ERROR;
const int64_t k_PCURLE_SEND_ERROR = CURLE_SEND_ERROR;
const int64_t k_PCURLE_SHARE_IN_USE = CURLE_SHARE_IN_USE;
const int64_t k_PCURLE_SSL_CACERT = CURLE_SSL_CACERT;
const int64_t k_PCURLE_SSL_CERTPROBLEM = CURLE_SSL_CERTPROBLEM;
const int64_t k_PCURLE_SSL_CIPHER = CURLE_SSL_CIPHER;
const int64_t k_PCURLE_SSL_CONNECT_ERROR = CURLE_SSL_CONNECT_ERROR;
const int64_t k_PCURLE_SSL_ENGINE_NOTFOUND = CURLE_SSL_ENGINE_NOTFOUND;
const int64_t k_PCURLE_SSL_ENGINE_SETFAILED = CURLE_SSL_ENGINE_SETFAILED;
const int64_t k_PCURLE_SSL_PEER_CERTIFICATE = CURLE_SSL_PEER_CERTIFICATE;
const int64_t k_PCURLE_TELNET_OPTION_SYNTAX = CURLE_TELNET_OPTION_SYNTAX;
const int64_t k_PCURLE_TOO_MANY_REDIRECTS = CURLE_TOO_MANY_REDIRECTS;
const int64_t k_PCURLE_UNKNOWN_TELNET_OPTION = CURLE_UNKNOWN_TELNET_OPTION;
const int64_t k_PCURLE_UNSUPPORTED_PROTOCOL = CURLE_UNSUPPORTED_PROTOCOL;
const int64_t k_PCURLE_URL_MALFORMAT = CURLE_URL_MALFORMAT;
const int64_t k_PCURLE_URL_MALFORMAT_USER = CURLE_URL_MALFORMAT_USER;
const int64_t k_PCURLE_WRITE_ERROR = CURLE_WRITE_ERROR;
const int64_t k_PCURLFTPAUTH_DEFAULT = CURLFTPAUTH_DEFAULT;
const int64_t k_PCURLFTPAUTH_SSL = CURLFTPAUTH_SSL;
const int64_t k_PCURLFTPAUTH_TLS = CURLFTPAUTH_TLS;
const int64_t k_PCURLFTPSSL_ALL = CURLFTPSSL_ALL;
const int64_t k_PCURLFTPSSL_CONTROL = CURLFTPSSL_CONTROL;
const int64_t k_PCURLFTPSSL_NONE = CURLFTPSSL_NONE;
const int64_t k_PCURLFTPSSL_TRY = CURLFTPSSL_TRY;
const int64_t k_PCURLINFO_CONNECT_TIME = CURLINFO_CONNECT_TIME;
const int64_t k_PCURLINFO_CONTENT_LENGTH_DOWNLOAD =
  CURLINFO_CONTENT_LENGTH_DOWNLOAD;
const int64_t k_PCURLINFO_CONTENT_LENGTH_UPLOAD = CURLINFO_CONTENT_LENGTH_UPLOAD;
const int64_t k_PCURLINFO_CONTENT_TYPE = CURLINFO_CONTENT_TYPE;
const int64_t k_PCURLINFO_EFFECTIVE_URL = CURLINFO_EFFECTIVE_URL;
const int64_t k_PCURLINFO_FILETIME = CURLINFO_FILETIME;
const int64_t k_PCURLINFO_HEADER_OUT = CURLINFO_HEADER_OUT;
const int64_t k_PCURLINFO_HEADER_SIZE = CURLINFO_HEADER_SIZE;
const int64_t k_PCURLINFO_HTTP_CODE = CURLINFO_HTTP_CODE;
const int64_t k_PCURLINFO_NAMELOOKUP_TIME = CURLINFO_NAMELOOKUP_TIME;
const int64_t k_PCURLINFO_PRETRANSFER_TIME = CURLINFO_PRETRANSFER_TIME;
const int64_t k_PCURLINFO_PRIVATE = CURLINFO_PRIVATE;
const int64_t k_PCURLINFO_REDIRECT_COUNT = CURLINFO_REDIRECT_COUNT;
const int64_t k_PCURLINFO_REDIRECT_TIME = CURLINFO_REDIRECT_TIME;
const int64_t k_PCURLINFO_REQUEST_SIZE = CURLINFO_REQUEST_SIZE;
const int64_t k_PCURLINFO_SIZE_DOWNLOAD = CURLINFO_SIZE_DOWNLOAD;
const int64_t k_PCURLINFO_SIZE_UPLOAD = CURLINFO_SIZE_UPLOAD;
const int64_t k_PCURLINFO_SPEED_DOWNLOAD = CURLINFO_SPEED_DOWNLOAD;
const int64_t k_PCURLINFO_SPEED_UPLOAD = CURLINFO_SPEED_UPLOAD;
const int64_t k_PCURLINFO_SSL_VERIFYRESULT = CURLINFO_SSL_VERIFYRESULT;
const int64_t k_PCURLINFO_STARTTRANSFER_TIME = CURLINFO_STARTTRANSFER_TIME;
const int64_t k_PCURLINFO_TOTAL_TIME = CURLINFO_TOTAL_TIME;
const int64_t k_PCURLMSG_DONE = CURLMSG_DONE;
const int64_t k_PCURLM_BAD_EASY_HANDLE = CURLM_BAD_EASY_HANDLE;
const int64_t k_PCURLM_BAD_HANDLE = CURLM_BAD_HANDLE;
const int64_t k_PCURLM_CALL_MULTI_PERFORM = CURLM_CALL_MULTI_PERFORM;
const int64_t k_PCURLM_INTERNAL_ERROR = CURLM_INTERNAL_ERROR;
const int64_t k_PCURLM_OK = CURLM_OK;
const int64_t k_PCURLM_OUT_OF_MEMORY = CURLM_OUT_OF_MEMORY;
const int64_t k_PCURLOPT_AUTOREFERER = CURLOPT_AUTOREFERER;
const int64_t k_PCURLOPT_BINARYTRANSFER = CURLOPT_BINARYTRANSFER;
const int64_t k_PCURLOPT_BUFFERSIZE = CURLOPT_BUFFERSIZE;
const int64_t k_PCURLOPT_CAINFO = CURLOPT_CAINFO;
const int64_t k_PCURLOPT_CAPATH = CURLOPT_CAPATH;
const int64_t k_PCURLOPT_CLOSEPOLICY = CURLOPT_CLOSEPOLICY;
const int64_t k_PCURLOPT_CONNECTTIMEOUT = CURLOPT_CONNECTTIMEOUT;
const int64_t k_PCURLOPT_COOKIE = CURLOPT_COOKIE;
const int64_t k_PCURLOPT_COOKIEFILE = CURLOPT_COOKIEFILE;
const int64_t k_PCURLOPT_COOKIEJAR = CURLOPT_COOKIEJAR;
const int64_t k_PCURLOPT_COOKIESESSION = CURLOPT_COOKIESESSION;
const int64_t k_PCURLOPT_CRLF = CURLOPT_CRLF;
const int64_t k_PCURLOPT_CUSTOMREQUEST = CURLOPT_CUSTOMREQUEST;
const int64_t k_PCURLOPT_DNS_CACHE_TIMEOUT = CURLOPT_DNS_CACHE_TIMEOUT;
const int64_t k_PCURLOPT_DNS_USE_GLOBAL_CACHE = CURLOPT_DNS_USE_GLOBAL_CACHE;
const int64_t k_PCURLOPT_EGDSOCKET = CURLOPT_EGDSOCKET;
const int64_t k_PCURLOPT_ENCODING = CURLOPT_ENCODING;
const int64_t k_PCURLOPT_FAILONERROR = CURLOPT_FAILONERROR;
const int64_t k_PCURLOPT_FILE = CURLOPT_FILE;
const int64_t k_PCURLOPT_FILETIME = CURLOPT_FILETIME;
const int64_t k_PCURLOPT_FOLLOWLOCATION = CURLOPT_FOLLOWLOCATION;
const int64_t k_PCURLOPT_FORBID_REUSE = CURLOPT_FORBID_REUSE;
const int64_t k_PCURLOPT_FRESH_CONNECT = CURLOPT_FRESH_CONNECT;
const int64_t k_PCURLOPT_FTPAPPEND = CURLOPT_FTPAPPEND;
const int64_t k_PCURLOPT_FTPLISTONLY = CURLOPT_FTPLISTONLY;
const int64_t k_PCURLOPT_FTPPORT = CURLOPT_FTPPORT;
const int64_t k_PCURLOPT_FTPSSLAUTH = CURLOPT_FTPSSLAUTH;
const int64_t k_PCURLOPT_FTP_CREATE_MISSING_DIRS =
  CURLOPT_FTP_CREATE_MISSING_DIRS;
const int64_t k_PCURLOPT_FTP_SSL = CURLOPT_FTP_SSL;
const int64_t k_PCURLOPT_FTP_USE_EPRT = CURLOPT_FTP_USE_EPRT;
const int64_t k_PCURLOPT_FTP_USE_EPSV = CURLOPT_FTP_USE_EPSV;
const int64_t k_PCURLOPT_HEADER = CURLOPT_HEADER;
const int64_t k_PCURLOPT_HEADERFUNCTION = CURLOPT_HEADERFUNCTION;
const int64_t k_PCURLOPT_HTTP200ALIASES = CURLOPT_HTTP200ALIASES;
const int64_t k_PCURLOPT_HTTPAUTH = CURLOPT_HTTPAUTH;
const int64_t k_PCURLOPT_HTTPGET = CURLOPT_HTTPGET;
const int64_t k_PCURLOPT_HTTPHEADER = CURLOPT_HTTPHEADER;
const int64_t k_PCURLOPT_HTTPPROXYTUNNEL = CURLOPT_HTTPPROXYTUNNEL;
const int64_t k_PCURLOPT_HTTP_VERSION = CURLOPT_HTTP_VERSION;
const int64_t k_PCURLOPT_INFILE = CURLOPT_INFILE;
const int64_t k_PCURLOPT_INFILESIZE = CURLOPT_INFILESIZE;
const int64_t k_PCURLOPT_INTERFACE = CURLOPT_INTERFACE;
const int64_t k_PCURLOPT_IPRESOLVE = CURLOPT_IPRESOLVE;
const int64_t k_PCURLOPT_KRB4LEVEL = CURLOPT_KRB4LEVEL;
const int64_t k_PCURLOPT_LOW_SPEED_LIMIT = CURLOPT_LOW_SPEED_LIMIT;
const int64_t k_PCURLOPT_LOW_SPEED_TIME = CURLOPT_LOW_SPEED_TIME;
const int64_t k_PCURLOPT_MAXCONNECTS = CURLOPT_MAXCONNECTS;
const int64_t k_PCURLOPT_MAXREDIRS = CURLOPT_MAXREDIRS;
const int64_t k_PCURLOPT_MUTE = CURLOPT_MUTE;
const int64_t k_PCURLOPT_NETRC = CURLOPT_NETRC;
const int64_t k_PCURLOPT_NOBODY = CURLOPT_NOBODY;
const int64_t k_PCURLOPT_NOPROGRESS = CURLOPT_NOPROGRESS;
const int64_t k_PCURLOPT_NOSIGNAL = CURLOPT_NOSIGNAL;
const int64_t k_PCURLOPT_PASSWDFUNCTION = CURLOPT_PASSWDFUNCTION;
const int64_t k_PCURLOPT_PORT = CURLOPT_PORT;
const int64_t k_PCURLOPT_POST = CURLOPT_POST;
const int64_t k_PCURLOPT_POSTFIELDS = CURLOPT_POSTFIELDS;
const int64_t k_PCURLOPT_POSTREDIR = CURLOPT_POSTREDIR;
const int64_t k_PCURLOPT_POSTQUOTE = CURLOPT_POSTQUOTE;
const int64_t k_PCURLOPT_PROTOCOLS = CURLOPT_PROTOCOLS;
const int64_t k_PCURLOPT_REDIR_PROTOCOLS = CURLOPT_REDIR_PROTOCOLS;
const int64_t k_PCURLOPT_PRIVATE = CURLOPT_PRIVATE;
const int64_t k_PCURLOPT_PROGRESSDATA = CURLOPT_PROGRESSDATA;
const int64_t k_PCURLOPT_PROGRESSFUNCTION = CURLOPT_PROGRESSFUNCTION;
const int64_t k_PCURLOPT_PROXY = CURLOPT_PROXY;
const int64_t k_PCURLOPT_PROXYAUTH = CURLOPT_PROXYAUTH;
const int64_t k_PCURLOPT_PROXYPORT = CURLOPT_PROXYPORT;
const int64_t k_PCURLOPT_PROXYTYPE = CURLOPT_PROXYTYPE;
const int64_t k_PCURLOPT_PROXYUSERPWD = CURLOPT_PROXYUSERPWD;
const int64_t k_PCURLOPT_PUT = CURLOPT_PUT;
const int64_t k_PCURLOPT_QUOTE = CURLOPT_QUOTE;
const int64_t k_PCURLOPT_RANDOM_FILE = CURLOPT_RANDOM_FILE;
const int64_t k_PCURLOPT_RANGE = CURLOPT_RANGE;
const int64_t k_PCURLOPT_READDATA = CURLOPT_READDATA;
const int64_t k_PCURLOPT_READFUNCTION = CURLOPT_READFUNCTION;
const int64_t k_PCURLOPT_REFERER = CURLOPT_REFERER;
const int64_t k_PCURLOPT_RESOLVE = CURLOPT_RESOLVE;
const int64_t k_PCURLOPT_RESUME_FROM = CURLOPT_RESUME_FROM;
const int64_t k_PCURLOPT_RETURNTRANSFER = CURLOPT_RETURNTRANSFER;
#ifdef FACEBOOK
const int64_t k_PCURLOPT_SERVICE_NAME = CURLOPT_SERVICE_NAME;
#endif
const int64_t k_PCURLOPT_SSLCERT = CURLOPT_SSLCERT;
const int64_t k_PCURLOPT_SSLCERTPASSWD = CURLOPT_SSLCERTPASSWD;
const int64_t k_PCURLOPT_SSLCERTTYPE = CURLOPT_SSLCERTTYPE;
const int64_t k_PCURLOPT_SSLENGINE = CURLOPT_SSLENGINE;
const int64_t k_PCURLOPT_SSLENGINE_DEFAULT = CURLOPT_SSLENGINE_DEFAULT;
const int64_t k_PCURLOPT_SSLKEY = CURLOPT_SSLKEY;
const int64_t k_PCURLOPT_SSLKEYPASSWD = CURLOPT_SSLKEYPASSWD;
const int64_t k_PCURLOPT_SSLKEYTYPE = CURLOPT_SSLKEYTYPE;
const int64_t k_PCURLOPT_SSLVERSION = CURLOPT_SSLVERSION;
const int64_t k_PCURLOPT_SSL_CIPHER_LIST = CURLOPT_SSL_CIPHER_LIST;
const int64_t k_PCURLOPT_SSL_VERIFYHOST = CURLOPT_SSL_VERIFYHOST;
const int64_t k_PCURLOPT_SSL_VERIFYPEER = CURLOPT_SSL_VERIFYPEER;
const int64_t k_PCURLOPT_STDERR = CURLOPT_STDERR;
const int64_t k_PCURLOPT_TCP_NODELAY = CURLOPT_TCP_NODELAY;
const int64_t k_PCURLOPT_TIMECONDITION = CURLOPT_TIMECONDITION;
const int64_t k_PCURLOPT_TIMEOUT = CURLOPT_TIMEOUT;
const int64_t k_PCURLOPT_TIMEVALUE = CURLOPT_TIMEVALUE;
const int64_t k_PCURLOPT_TRANSFERTEXT = CURLOPT_TRANSFERTEXT;
const int64_t k_PCURLOPT_UNRESTRICTED_AUTH = CURLOPT_UNRESTRICTED_AUTH;
const int64_t k_PCURLOPT_UPLOAD = CURLOPT_UPLOAD;
const int64_t k_PCURLOPT_URL = CURLOPT_URL;
const int64_t k_PCURLOPT_USERAGENT = CURLOPT_USERAGENT;
const int64_t k_PCURLOPT_USERPWD = CURLOPT_USERPWD;
const int64_t k_PCURLOPT_VERBOSE = CURLOPT_VERBOSE;
const int64_t k_PCURLOPT_WRITEFUNCTION = CURLOPT_WRITEFUNCTION;
const int64_t k_PCURLOPT_WRITEHEADER = CURLOPT_WRITEHEADER;
const int64_t k_PCURLOPT_FB_TLS_VER_MAX =
  PCurlResource::fb_specific_options::CURLOPT_FB_TLS_VER_MAX;
const int64_t k_PCURLOPT_FB_TLS_VER_MAX_NONE =
  PCurlResource::fb_specific_options::CURLOPT_FB_TLS_VER_MAX_NONE;
const int64_t k_PCURLOPT_FB_TLS_VER_MAX_1_1 =
  PCurlResource::fb_specific_options::CURLOPT_FB_TLS_VER_MAX_1_1;
const int64_t k_PCURLOPT_FB_TLS_VER_MAX_1_0 =
  PCurlResource::fb_specific_options::CURLOPT_FB_TLS_VER_MAX_1_0;
const int64_t k_PCURLOPT_FB_TLS_CIPHER_SPEC =
  PCurlResource::fb_specific_options::CURLOPT_FB_TLS_CIPHER_SPEC;
const int64_t k_PCURLPROXY_HTTP = CURLPROXY_HTTP;
const int64_t k_PCURLPROXY_SOCKS5 = CURLPROXY_SOCKS5;
const int64_t k_PCURLVERSION_NOW = CURLVERSION_NOW;
const int64_t k_PCURL_HTTP_VERSION_1_0 = CURL_HTTP_VERSION_1_0;
const int64_t k_PCURL_HTTP_VERSION_1_1 = CURL_HTTP_VERSION_1_1;
const int64_t k_PCURL_HTTP_VERSION_NONE = CURL_HTTP_VERSION_NONE;
const int64_t k_PCURL_IPRESOLVE_V4 = CURL_IPRESOLVE_V4;
const int64_t k_PCURL_IPRESOLVE_V6 = CURL_IPRESOLVE_V6;
const int64_t k_PCURL_IPRESOLVE_WHATEVER = CURL_IPRESOLVE_WHATEVER;
const int64_t k_PCURL_NETRC_IGNORED = CURL_NETRC_IGNORED;
const int64_t k_PCURL_NETRC_OPTIONAL = CURL_NETRC_OPTIONAL;
const int64_t k_PCURL_NETRC_REQUIRED = CURL_NETRC_REQUIRED;
const int64_t k_PCURL_TIMECOND_IFMODSINCE = CURL_TIMECOND_IFMODSINCE;
const int64_t k_PCURL_TIMECOND_IFUNMODSINCE = CURL_TIMECOND_IFUNMODSINCE;
const int64_t k_PCURL_TIMECOND_LASTMOD = CURL_TIMECOND_LASTMOD;
const int64_t k_PCURL_VERSION_IPV6 = CURL_VERSION_IPV6;
const int64_t k_PCURL_VERSION_KERBEROS4 = CURL_VERSION_KERBEROS4;
const int64_t k_PCURL_VERSION_LIBZ = CURL_VERSION_LIBZ;
const int64_t k_PCURL_VERSION_SSL = CURL_VERSION_SSL;

const int64_t k_PCURLPROTO_HTTP = CURLPROTO_HTTP;
const int64_t k_PCURLPROTO_HTTPS = CURLPROTO_HTTPS;
const int64_t k_PCURLPROTO_FTP = CURLPROTO_FTP;
const int64_t k_PCURLPROTO_FTPS = CURLPROTO_FTPS;
const int64_t k_PCURLPROTO_SCP = CURLPROTO_SCP;
const int64_t k_PCURLPROTO_SFTP = CURLPROTO_SFTP;
const int64_t k_PCURLPROTO_TELNET = CURLPROTO_TELNET;
const int64_t k_PCURLPROTO_LDAP = CURLPROTO_LDAP;
const int64_t k_PCURLPROTO_LDAPS = CURLPROTO_LDAPS;
const int64_t k_PCURLPROTO_DICT = CURLPROTO_DICT;
const int64_t k_PCURLPROTO_FILE = CURLPROTO_FILE;
const int64_t k_PCURLPROTO_TFTP = CURLPROTO_TFTP;
const int64_t k_PCURLPROTO_ALL = CURLPROTO_ALL;

///////////////////////////////////////////////////////////////////////////////

#if LIBCURL_VERSION_NUM >= 0x071500
const StaticString s_PCURLINFO_LOCAL_PORT("PCURLINFO_LOCAL_PORT");
#endif
#if LIBCURL_VERSION_NUM >= 0x071002
const StaticString s_CURLOPT_TIMEOUT_MS("CURLOPT_TIMEOUT_MS");
const StaticString s_CURLOPT_CONNECTTIMEOUT_MS("CURLOPT_CONNECTTIMEOUT_MS");
#endif
const StaticString s_PCURLAUTH_ANY("PCURLAUTH_ANY");
const StaticString s_PCURLAUTH_ANYSAFE("PCURLAUTH_ANYSAFE");
const StaticString s_PCURLAUTH_BASIC("PCURLAUTH_BASIC");
const StaticString s_PCURLAUTH_DIGEST("PCURLAUTH_DIGEST");
const StaticString s_PCURLAUTH_GSSNEGOTIATE("PCURLAUTH_GSSNEGOTIATE");
const StaticString s_PCURLAUTH_NTLM("PCURLAUTH_NTLM");
const StaticString s_PCURLCLOSEPOLICY_CALLBACK("PCURLCLOSEPOLICY_CALLBACK");
const StaticString
  s_PCURLCLOSEPOLICY_LEAST_RECENTLY_USED("PCURLCLOSEPOLICY_LEAST_RECENTLY_USED");
const StaticString
  s_PCURLCLOSEPOLICY_LEAST_TRAFFIC("PCURLCLOSEPOLICY_LEAST_TRAFFIC");
const StaticString s_PCURLCLOSEPOLICY_OLDEST("PCURLCLOSEPOLICY_OLDEST");
const StaticString s_PCURLCLOSEPOLICY_SLOWEST("PCURLCLOSEPOLICY_SLOWEST");
const StaticString s_PCURLE_ABORTED_BY_CALLBACK("PCURLE_ABORTED_BY_CALLBACK");
const StaticString s_PCURLE_BAD_CALLING_ORDER("PCURLE_BAD_CALLING_ORDER");
const StaticString s_PCURLE_BAD_CONTENT_ENCODING("PCURLE_BAD_CONTENT_ENCODING");
const StaticString s_PCURLE_BAD_FUNCTION_ARGUMENT("PCURLE_BAD_FUNCTION_ARGUMENT");
const StaticString s_PCURLE_BAD_PASSWORD_ENTERED("PCURLE_BAD_PASSWORD_ENTERED");
const StaticString s_PCURLE_COULDNT_CONNECT("PCURLE_COULDNT_CONNECT");
const StaticString s_PCURLE_COULDNT_RESOLVE_HOST("PCURLE_COULDNT_RESOLVE_HOST");
const StaticString s_PCURLE_COULDNT_RESOLVE_PROXY("PCURLE_COULDNT_RESOLVE_PROXY");
const StaticString s_PCURLE_FAILED_INIT("PCURLE_FAILED_INIT");
const StaticString s_PCURLE_FILESIZE_EXCEEDED("PCURLE_FILESIZE_EXCEEDED");
const StaticString
  s_PCURLE_FILE_COULDNT_READ_FILE("PCURLE_FILE_COULDNT_READ_FILE");
const StaticString s_PCURLE_FTP_ACCESS_DENIED("PCURLE_FTP_ACCESS_DENIED");
const StaticString
  s_PCURLE_FTP_BAD_DOWNLOAD_RESUME("PCURLE_FTP_BAD_DOWNLOAD_RESUME");
const StaticString s_PCURLE_FTP_CANT_GET_HOST("PCURLE_FTP_CANT_GET_HOST");
const StaticString s_PCURLE_FTP_CANT_RECONNECT("PCURLE_FTP_CANT_RECONNECT");
const StaticString s_PCURLE_FTP_COULDNT_GET_SIZE("PCURLE_FTP_COULDNT_GET_SIZE");
const StaticString s_PCURLE_FTP_COULDNT_RETR_FILE("PCURLE_FTP_COULDNT_RETR_FILE");
const StaticString s_PCURLE_FTP_COULDNT_SET_ASCII("PCURLE_FTP_COULDNT_SET_ASCII");
const StaticString
  s_PCURLE_FTP_COULDNT_SET_BINARY("PCURLE_FTP_COULDNT_SET_BINARY");
const StaticString s_PCURLE_FTP_COULDNT_STOR_FILE("PCURLE_FTP_COULDNT_STOR_FILE");
const StaticString s_PCURLE_FTP_COULDNT_USE_REST("PCURLE_FTP_COULDNT_USE_REST");
const StaticString s_PCURLE_FTP_PORT_FAILED("PCURLE_FTP_PORT_FAILED");
const StaticString s_PCURLE_FTP_QUOTE_ERROR("PCURLE_FTP_QUOTE_ERROR");
const StaticString s_PCURLE_FTP_SSL_FAILED("PCURLE_FTP_SSL_FAILED");
const StaticString
  s_PCURLE_FTP_USER_PASSWORD_INCORRECT("PCURLE_FTP_USER_PASSWORD_INCORRECT");
const StaticString s_PCURLE_FTP_WEIRD_227_FORMAT("PCURLE_FTP_WEIRD_227_FORMAT");
const StaticString s_PCURLE_FTP_WEIRD_PASS_REPLY("PCURLE_FTP_WEIRD_PASS_REPLY");
const StaticString s_PCURLE_FTP_WEIRD_PASV_REPLY("PCURLE_FTP_WEIRD_PASV_REPLY");
const StaticString
  s_PCURLE_FTP_WEIRD_SERVER_REPLY("PCURLE_FTP_WEIRD_SERVER_REPLY");
const StaticString s_PCURLE_FTP_WEIRD_USER_REPLY("PCURLE_FTP_WEIRD_USER_REPLY");
const StaticString s_PCURLE_FTP_WRITE_ERROR("PCURLE_FTP_WRITE_ERROR");
const StaticString s_PCURLE_FUNCTION_NOT_FOUND("PCURLE_FUNCTION_NOT_FOUND");
const StaticString s_PCURLE_GOT_NOTHING("PCURLE_GOT_NOTHING");
const StaticString s_PCURLE_HTTP_NOT_FOUND("PCURLE_HTTP_NOT_FOUND");
const StaticString s_PCURLE_HTTP_PORT_FAILED("PCURLE_HTTP_PORT_FAILED");
const StaticString s_PCURLE_HTTP_POST_ERROR("PCURLE_HTTP_POST_ERROR");
const StaticString s_PCURLE_HTTP_RANGE_ERROR("PCURLE_HTTP_RANGE_ERROR");
const StaticString s_PCURLE_LDAP_CANNOT_BIND("PCURLE_LDAP_CANNOT_BIND");
const StaticString s_PCURLE_LDAP_INVALID_URL("PCURLE_LDAP_INVALID_URL");
const StaticString s_PCURLE_LDAP_SEARCH_FAILED("PCURLE_LDAP_SEARCH_FAILED");
const StaticString s_PCURLE_LIBRARY_NOT_FOUND("PCURLE_LIBRARY_NOT_FOUND");
const StaticString s_PCURLE_MALFORMAT_USER("PCURLE_MALFORMAT_USER");
const StaticString s_PCURLE_OBSOLETE("PCURLE_OBSOLETE");
const StaticString s_PCURLE_OK("PCURLE_OK");
const StaticString s_PCURLE_OPERATION_TIMEDOUT("PCURLE_OPERATION_TIMEDOUT");
const StaticString s_PCURLE_OPERATION_TIMEOUTED("PCURLE_OPERATION_TIMEOUTED");
const StaticString s_PCURLE_OUT_OF_MEMORY("PCURLE_OUT_OF_MEMORY");
const StaticString s_PCURLE_PARTIAL_FILE("PCURLE_PARTIAL_FILE");
const StaticString s_PCURLE_READ_ERROR("PCURLE_READ_ERROR");
const StaticString s_PCURLE_RECV_ERROR("PCURLE_RECV_ERROR");
const StaticString s_PCURLE_SEND_ERROR("PCURLE_SEND_ERROR");
const StaticString s_PCURLE_SHARE_IN_USE("PCURLE_SHARE_IN_USE");
const StaticString s_PCURLE_SSL_CACERT("PCURLE_SSL_CACERT");
const StaticString s_PCURLE_SSL_CERTPROBLEM("PCURLE_SSL_CERTPROBLEM");
const StaticString s_PCURLE_SSL_CIPHER("PCURLE_SSL_CIPHER");
const StaticString s_PCURLE_SSL_CONNECT_ERROR("PCURLE_SSL_CONNECT_ERROR");
const StaticString s_PCURLE_SSL_ENGINE_NOTFOUND("PCURLE_SSL_ENGINE_NOTFOUND");
const StaticString s_PCURLE_SSL_ENGINE_SETFAILED("PCURLE_SSL_ENGINE_SETFAILED");
const StaticString s_PCURLE_SSL_PEER_CERTIFICATE("PCURLE_SSL_PEER_CERTIFICATE");
const StaticString s_PCURLE_TELNET_OPTION_SYNTAX("PCURLE_TELNET_OPTION_SYNTAX");
const StaticString s_PCURLE_TOO_MANY_REDIRECTS("PCURLE_TOO_MANY_REDIRECTS");
const StaticString s_PCURLE_UNKNOWN_TELNET_OPTION("PCURLE_UNKNOWN_TELNET_OPTION");
const StaticString s_PCURLE_UNSUPPORTED_PROTOCOL("PCURLE_UNSUPPORTED_PROTOCOL");
const StaticString s_PCURLE_URL_MALFORMAT("PCURLE_URL_MALFORMAT");
const StaticString s_PCURLE_URL_MALFORMAT_USER("PCURLE_URL_MALFORMAT_USER");
const StaticString s_PCURLE_WRITE_ERROR("PCURLE_WRITE_ERROR");
const StaticString s_PCURLFTPAUTH_DEFAULT("PCURLFTPAUTH_DEFAULT");
const StaticString s_PCURLFTPAUTH_SSL("PCURLFTPAUTH_SSL");
const StaticString s_PCURLFTPAUTH_TLS("PCURLFTPAUTH_TLS");
const StaticString s_PCURLFTPSSL_ALL("PCURLFTPSSL_ALL");
const StaticString s_PCURLFTPSSL_CONTROL("PCURLFTPSSL_CONTROL");
const StaticString s_PCURLFTPSSL_NONE("PCURLFTPSSL_NONE");
const StaticString s_PCURLFTPSSL_TRY("PCURLFTPSSL_TRY");
const StaticString s_PCURLINFO_CONNECT_TIME("PCURLINFO_CONNECT_TIME");
const StaticString
  s_PCURLINFO_CONTENT_LENGTH_DOWNLOAD("PCURLINFO_CONTENT_LENGTH_DOWNLOAD");
const StaticString
  s_PCURLINFO_CONTENT_LENGTH_UPLOAD("PCURLINFO_CONTENT_LENGTH_UPLOAD");
const StaticString s_PCURLINFO_CONTENT_TYPE("PCURLINFO_CONTENT_TYPE");
const StaticString s_PCURLINFO_EFFECTIVE_URL("PCURLINFO_EFFECTIVE_URL");
const StaticString s_PCURLINFO_FILETIME("PCURLINFO_FILETIME");
const StaticString s_PCURLINFO_HEADER_OUT("PCURLINFO_HEADER_OUT");
const StaticString s_PCURLINFO_HEADER_SIZE("PCURLINFO_HEADER_SIZE");
const StaticString s_PCURLINFO_HTTP_CODE("PCURLINFO_HTTP_CODE");
const StaticString s_PCURLINFO_NAMELOOKUP_TIME("PCURLINFO_NAMELOOKUP_TIME");
const StaticString s_PCURLINFO_PRETRANSFER_TIME("PCURLINFO_PRETRANSFER_TIME");
const StaticString s_PCURLINFO_PRIVATE("PCURLINFO_PRIVATE");
const StaticString s_PCURLINFO_REDIRECT_COUNT("PCURLINFO_REDIRECT_COUNT");
const StaticString s_PCURLINFO_REDIRECT_TIME("PCURLINFO_REDIRECT_TIME");
const StaticString s_PCURLINFO_REQUEST_SIZE("PCURLINFO_REQUEST_SIZE");
const StaticString s_PCURLINFO_SIZE_DOWNLOAD("PCURLINFO_SIZE_DOWNLOAD");
const StaticString s_PCURLINFO_SIZE_UPLOAD("PCURLINFO_SIZE_UPLOAD");
const StaticString s_PCURLINFO_SPEED_DOWNLOAD("PCURLINFO_SPEED_DOWNLOAD");
const StaticString s_PCURLINFO_SPEED_UPLOAD("PCURLINFO_SPEED_UPLOAD");
const StaticString s_PCURLINFO_SSL_VERIFYRESULT("PCURLINFO_SSL_VERIFYRESULT");
const StaticString s_PCURLINFO_STARTTRANSFER_TIME("PCURLINFO_STARTTRANSFER_TIME");
const StaticString s_PCURLINFO_TOTAL_TIME("PCURLINFO_TOTAL_TIME");
const StaticString s_PCURLMSG_DONE("PCURLMSG_DONE");
const StaticString s_PCURLM_BAD_EASY_HANDLE("PCURLM_BAD_EASY_HANDLE");
const StaticString s_PCURLM_BAD_HANDLE("PCURLM_BAD_HANDLE");
const StaticString s_PCURLM_CALL_MULTI_PERFORM("PCURLM_CALL_MULTI_PERFORM");
const StaticString s_PCURLM_INTERNAL_ERROR("PCURLM_INTERNAL_ERROR");
const StaticString s_PCURLM_OK("PCURLM_OK");
const StaticString s_PCURLM_OUT_OF_MEMORY("PCURLM_OUT_OF_MEMORY");
const StaticString s_PCURLOPT_AUTOREFERER("PCURLOPT_AUTOREFERER");
const StaticString s_PCURLOPT_BINARYTRANSFER("PCURLOPT_BINARYTRANSFER");
const StaticString s_PCURLOPT_BUFFERSIZE("PCURLOPT_BUFFERSIZE");
const StaticString s_PCURLOPT_CAINFO("PCURLOPT_CAINFO");
const StaticString s_PCURLOPT_CAPATH("PCURLOPT_CAPATH");
const StaticString s_PCURLOPT_CLOSEPOLICY("PCURLOPT_CLOSEPOLICY");
const StaticString s_PCURLOPT_CONNECTTIMEOUT("PCURLOPT_CONNECTTIMEOUT");
const StaticString s_PCURLOPT_COOKIE("PCURLOPT_COOKIE");
const StaticString s_PCURLOPT_COOKIEFILE("PCURLOPT_COOKIEFILE");
const StaticString s_PCURLOPT_COOKIEJAR("PCURLOPT_COOKIEJAR");
const StaticString s_PCURLOPT_COOKIESESSION("PCURLOPT_COOKIESESSION");
const StaticString s_PCURLOPT_CRLF("PCURLOPT_CRLF");
const StaticString s_PCURLOPT_CUSTOMREQUEST("PCURLOPT_CUSTOMREQUEST");
const StaticString s_PCURLOPT_DNS_CACHE_TIMEOUT("PCURLOPT_DNS_CACHE_TIMEOUT");
const StaticString
  s_PCURLOPT_DNS_USE_GLOBAL_CACHE("PCURLOPT_DNS_USE_GLOBAL_CACHE");
const StaticString s_PCURLOPT_EGDSOCKET("PCURLOPT_EGDSOCKET");
const StaticString s_PCURLOPT_ENCODING("PCURLOPT_ENCODING");
const StaticString s_PCURLOPT_FAILONERROR("PCURLOPT_FAILONERROR");
const StaticString s_PCURLOPT_FILE("PCURLOPT_FILE");
const StaticString s_PCURLOPT_FILETIME("PCURLOPT_FILETIME");
const StaticString s_PCURLOPT_FOLLOWLOCATION("PCURLOPT_FOLLOWLOCATION");
const StaticString s_PCURLOPT_FORBID_REUSE("PCURLOPT_FORBID_REUSE");
const StaticString s_PCURLOPT_FRESH_CONNECT("PCURLOPT_FRESH_CONNECT");
const StaticString s_PCURLOPT_FTPAPPEND("PCURLOPT_FTPAPPEND");
const StaticString s_PCURLOPT_FTPLISTONLY("PCURLOPT_FTPLISTONLY");
const StaticString s_PCURLOPT_FTPPORT("PCURLOPT_FTPPORT");
const StaticString s_PCURLOPT_FTPSSLAUTH("PCURLOPT_FTPSSLAUTH");
const StaticString
  s_PCURLOPT_FTP_CREATE_MISSING_DIRS("PCURLOPT_FTP_CREATE_MISSING_DIRS");
const StaticString s_PCURLOPT_FTP_SSL("PCURLOPT_FTP_SSL");
const StaticString s_PCURLOPT_FTP_USE_EPRT("PCURLOPT_FTP_USE_EPRT");
const StaticString s_PCURLOPT_FTP_USE_EPSV("PCURLOPT_FTP_USE_EPSV");
const StaticString s_PCURLOPT_HEADER("PCURLOPT_HEADER");
const StaticString s_PCURLOPT_HEADERFUNCTION("PCURLOPT_HEADERFUNCTION");
const StaticString s_PCURLOPT_HTTP200ALIASES("PCURLOPT_HTTP200ALIASES");
const StaticString s_PCURLOPT_HTTPAUTH("PCURLOPT_HTTPAUTH");
const StaticString s_PCURLOPT_HTTPGET("PCURLOPT_HTTPGET");
const StaticString s_PCURLOPT_HTTPHEADER("PCURLOPT_HTTPHEADER");
const StaticString s_PCURLOPT_HTTPPROXYTUNNEL("PCURLOPT_HTTPPROXYTUNNEL");
const StaticString s_PCURLOPT_HTTP_VERSION("PCURLOPT_HTTP_VERSION");
const StaticString s_PCURLOPT_INFILE("PCURLOPT_INFILE");
const StaticString s_PCURLOPT_INFILESIZE("PCURLOPT_INFILESIZE");
const StaticString s_PCURLOPT_INTERFACE("PCURLOPT_INTERFACE");
const StaticString s_PCURLOPT_IPRESOLVE("PCURLOPT_IPRESOLVE");
const StaticString s_PCURLOPT_KRB4LEVEL("PCURLOPT_KRB4LEVEL");
const StaticString s_PCURLOPT_LOW_SPEED_LIMIT("PCURLOPT_LOW_SPEED_LIMIT");
const StaticString s_PCURLOPT_LOW_SPEED_TIME("PCURLOPT_LOW_SPEED_TIME");
const StaticString s_PCURLOPT_MAXCONNECTS("PCURLOPT_MAXCONNECTS");
const StaticString s_PCURLOPT_MAXREDIRS("PCURLOPT_MAXREDIRS");
const StaticString s_PCURLOPT_MUTE("PCURLOPT_MUTE");
const StaticString s_PCURLOPT_NETRC("PCURLOPT_NETRC");
const StaticString s_PCURLOPT_NOBODY("PCURLOPT_NOBODY");
const StaticString s_PCURLOPT_NOPROGRESS("PCURLOPT_NOPROGRESS");
const StaticString s_PCURLOPT_NOSIGNAL("PCURLOPT_NOSIGNAL");
const StaticString s_PCURLOPT_PASSWDFUNCTION("PCURLOPT_PASSWDFUNCTION");
const StaticString s_PCURLOPT_PORT("PCURLOPT_PORT");
const StaticString s_PCURLOPT_POST("PCURLOPT_POST");
const StaticString s_PCURLOPT_POSTFIELDS("PCURLOPT_POSTFIELDS");
const StaticString s_PCURLOPT_POSTREDIR("PCURLOPT_POSTREDIR");
const StaticString s_PCURLOPT_PROTOCOLS("PCURLOPT_PROTOCOLS");
const StaticString s_PCURLOPT_REDIR_PROTOCOLS("PCURLOPT_REDIR_PROTOCOLS");
const StaticString s_PCURLOPT_POSTQUOTE("PCURLOPT_POSTQUOTE");
const StaticString s_PCURLOPT_PRIVATE("PCURLOPT_PRIVATE");
const StaticString s_PCURLOPT_PROGRESSFUNCTION("PCURLOPT_PROGRESSFUNCTION");
const StaticString s_PCURLOPT_PROXY("PCURLOPT_PROXY");
const StaticString s_PCURLOPT_PROXYAUTH("PCURLOPT_PROXYAUTH");
const StaticString s_PCURLOPT_PROXYPORT("PCURLOPT_PROXYPORT");
const StaticString s_PCURLOPT_PROXYTYPE("PCURLOPT_PROXYTYPE");
const StaticString s_PCURLOPT_PROXYUSERPWD("PCURLOPT_PROXYUSERPWD");
const StaticString s_PCURLOPT_PUT("PCURLOPT_PUT");
const StaticString s_PCURLOPT_QUOTE("PCURLOPT_QUOTE");
const StaticString s_PCURLOPT_RANDOM_FILE("PCURLOPT_RANDOM_FILE");
const StaticString s_PCURLOPT_RANGE("PCURLOPT_RANGE");
const StaticString s_PCURLOPT_READDATA("PCURLOPT_READDATA");
const StaticString s_PCURLOPT_READFUNCTION("PCURLOPT_READFUNCTION");
const StaticString s_PCURLOPT_REFERER("PCURLOPT_REFERER");
const StaticString s_PCURLOPT_RESOLVE("PCURLOPT_RESOLVE");
const StaticString s_PCURLOPT_RESUME_FROM("PCURLOPT_RESUME_FROM");
const StaticString s_PCURLOPT_RETURNTRANSFER("PCURLOPT_RETURNTRANSFER");
#ifdef FACEBOOK
const StaticString s_PCURLOPT_SERVICE_NAME("PCURLOPT_SERVICE_NAME");
#endif
const StaticString s_PCURLOPT_SSLCERT("PCURLOPT_SSLCERT");
const StaticString s_PCURLOPT_SSLCERTPASSWD("PCURLOPT_SSLCERTPASSWD");
const StaticString s_PCURLOPT_SSLCERTTYPE("PCURLOPT_SSLCERTTYPE");
const StaticString s_PCURLOPT_SSLENGINE("PCURLOPT_SSLENGINE");
const StaticString s_PCURLOPT_SSLENGINE_DEFAULT("PCURLOPT_SSLENGINE_DEFAULT");
const StaticString s_PCURLOPT_SSLKEY("PCURLOPT_SSLKEY");
const StaticString s_PCURLOPT_SSLKEYPASSWD("PCURLOPT_SSLKEYPASSWD");
const StaticString s_PCURLOPT_SSLKEYTYPE("PCURLOPT_SSLKEYTYPE");
const StaticString s_PCURLOPT_SSLVERSION("PCURLOPT_SSLVERSION");
const StaticString s_PCURLOPT_SSL_CIPHER_LIST("PCURLOPT_SSL_CIPHER_LIST");
const StaticString s_PCURLOPT_SSL_VERIFYHOST("PCURLOPT_SSL_VERIFYHOST");
const StaticString s_PCURLOPT_SSL_VERIFYPEER("PCURLOPT_SSL_VERIFYPEER");
const StaticString s_PCURLOPT_STDERR("PCURLOPT_STDERR");
const StaticString s_PCURLOPT_TCP_NODELAY("PCURLOPT_TCP_NODELAY");
const StaticString s_PCURLOPT_TIMECONDITION("PCURLOPT_TIMECONDITION");
const StaticString s_PCURLOPT_TIMEOUT("PCURLOPT_TIMEOUT");
const StaticString s_PCURLOPT_TIMEVALUE("PCURLOPT_TIMEVALUE");
const StaticString s_PCURLOPT_TRANSFERTEXT("PCURLOPT_TRANSFERTEXT");
const StaticString s_PCURLOPT_UNRESTRICTED_AUTH("PCURLOPT_UNRESTRICTED_AUTH");
const StaticString s_PCURLOPT_UPLOAD("PCURLOPT_UPLOAD");
const StaticString s_PCURLOPT_URL("PCURLOPT_URL");
const StaticString s_PCURLOPT_USERAGENT("PCURLOPT_USERAGENT");
const StaticString s_PCURLOPT_USERPWD("PCURLOPT_USERPWD");
const StaticString s_PCURLOPT_VERBOSE("PCURLOPT_VERBOSE");
const StaticString s_PCURLOPT_WRITEFUNCTION("PCURLOPT_WRITEFUNCTION");
const StaticString s_PCURLOPT_WRITEHEADER("PCURLOPT_WRITEHEADER");
const StaticString s_PCURLOPT_FB_TLS_VER_MAX("PCURLOPT_FB_TLS_VER_MAX");
const StaticString s_PCURLOPT_FB_TLS_VER_MAX_NONE("PCURLOPT_FB_TLS_VER_MAX_NONE");
const StaticString s_PCURLOPT_FB_TLS_VER_MAX_1_1("PCURLOPT_FB_TLS_VER_MAX_1_1");
const StaticString s_PCURLOPT_FB_TLS_VER_MAX_1_0("PCURLOPT_FB_TLS_VER_MAX_1_0");
const StaticString s_PCURLOPT_FB_TLS_CIPHER_SPEC("PCURLOPT_FB_TLS_CIPHER_SPEC");
const StaticString s_PCURLPROXY_HTTP("PCURLPROXY_HTTP");
const StaticString s_PCURLPROXY_SOCKS5("PCURLPROXY_SOCKS5");
const StaticString s_PCURLVERSION_NOW("PCURLVERSION_NOW");
const StaticString s_PCURL_HTTP_VERSION_1_0("PCURL_HTTP_VERSION_1_0");
const StaticString s_PCURL_HTTP_VERSION_1_1("PCURL_HTTP_VERSION_1_1");
const StaticString s_PCURL_HTTP_VERSION_NONE("PCURL_HTTP_VERSION_NONE");
const StaticString s_PCURL_IPRESOLVE_V4("PCURL_IPRESOLVE_V4");
const StaticString s_PCURL_IPRESOLVE_V6("PCURL_IPRESOLVE_V6");
const StaticString s_PCURL_IPRESOLVE_WHATEVER("PCURL_IPRESOLVE_WHATEVER");
const StaticString s_PCURL_NETRC_IGNORED("PCURL_NETRC_IGNORED");
const StaticString s_PCURL_NETRC_OPTIONAL("PCURL_NETRC_OPTIONAL");
const StaticString s_PCURL_NETRC_REQUIRED("PCURL_NETRC_REQUIRED");
const StaticString s_PCURL_TIMECOND_IFMODSINCE("PCURL_TIMECOND_IFMODSINCE");
const StaticString s_PCURL_TIMECOND_IFUNMODSINCE("PCURL_TIMECOND_IFUNMODSINCE");
const StaticString s_PCURL_TIMECOND_LASTMOD("PCURL_TIMECOND_LASTMOD");
const StaticString s_PCURL_VERSION_IPV6("PCURL_VERSION_IPV6");
const StaticString s_PCURL_VERSION_KERBEROS4("PCURL_VERSION_KERBEROS4");
const StaticString s_PCURL_VERSION_LIBZ("PCURL_VERSION_LIBZ");
const StaticString s_PCURL_VERSION_SSL("PCURL_VERSION_SSL");

const StaticString s_PCURLPROTO_HTTP("PCURLPROTO_HTTP");
const StaticString s_PCURLPROTO_HTTPS("PCURLPROTO_HTTPS");
const StaticString s_PCURLPROTO_FTP("PCURLPROTO_FTP");
const StaticString s_PCURLPROTO_FTPS("PCURLPROTO_FTPS");
const StaticString s_PCURLPROTO_SCP("PCURLPROTO_SCP");
const StaticString s_PCURLPROTO_SFTP("PCURLPROTO_SFTP");
const StaticString s_PCURLPROTO_TELNET("PCURLPROTO_TELNET");
const StaticString s_PCURLPROTO_LDAP("PCURLPROTO_LDAP");
const StaticString s_PCURLPROTO_LDAPS("PCURLPROTO_LDAPS");
const StaticString s_PCURLPROTO_DICT("PCURLPROTO_DICT");
const StaticString s_PCURLPROTO_FILE("PCURLPROTO_FILE");
const StaticString s_PCURLPROTO_TFTP("PCURLPROTO_TFTP");
const StaticString s_PCURLPROTO_ALL("PCURLPROTO_ALL");

static int s_poolSize, s_reuseLimit, s_getTimeout;
static std::string s_namedPools;

class PCurlExtension final : public Extension {
  /* CUSTOM_START */
  private:
    int threadCount = 10;
    int cleanupIntervalSec = 60;
  /* CUSTOM_END */

 public:
  PCurlExtension() : Extension("pcurl") {}

  /* CUSTOM_START */
  virtual void moduleLoad(const IniSetting::Map& ini, Hdf hdf) {
    //Hdf hdf_pcurl = hdf["PCurl"];
    //Hdf hdf_server = hdf["Server"];

    //threadCount = Config::GetInt32(ini, hdf, "ThreadCount", 10, false);
    //cleanupIntervalSec =
    //  Config::GetInt32(ini, hdf, "CleanupIntervalSec", 60, false);

    //_LOG("extension pcurl: created");
  }
  /* CUSTOM_END */

  void moduleInit() override {
    /* CUSTOM_START */
    hostSocketFdPool =
      std::make_shared<HostSocketFdPool>(threadCount, cleanupIntervalSec);
    //registerConstants();
    //registerFunctions();
    loadSystemlib();
    //_LOG("extension pcurl: initialized");
    /* CUSTOM_END */

#if LIBCURL_VERSION_NUM >= 0x071500
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_LOCAL_PORT.get(), k_PCURLINFO_LOCAL_PORT
    );
#endif
/*#if LIBCURL_VERSION_NUM >= 0x071002
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_TIMEOUT_MS.get(), k_PCURLOPT_TIMEOUT_MS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_CONNECTTIMEOUT_MS.get(), k_PCURLOPT_CONNECTTIMEOUT_MS
    );
#endif*/
    Native::registerConstant<KindOfInt64>(
      s_PCURLAUTH_ANY.get(), k_PCURLAUTH_ANY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLAUTH_ANYSAFE.get(), k_PCURLAUTH_ANYSAFE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLAUTH_BASIC.get(), k_PCURLAUTH_BASIC
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLAUTH_DIGEST.get(), k_PCURLAUTH_DIGEST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLAUTH_GSSNEGOTIATE.get(), k_PCURLAUTH_GSSNEGOTIATE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLAUTH_NTLM.get(), k_PCURLAUTH_NTLM
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLCLOSEPOLICY_CALLBACK.get(), k_PCURLCLOSEPOLICY_CALLBACK
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLCLOSEPOLICY_LEAST_RECENTLY_USED.get(),
      k_PCURLCLOSEPOLICY_LEAST_RECENTLY_USED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLCLOSEPOLICY_LEAST_TRAFFIC.get(), k_PCURLCLOSEPOLICY_LEAST_TRAFFIC
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLCLOSEPOLICY_OLDEST.get(), k_PCURLCLOSEPOLICY_OLDEST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLCLOSEPOLICY_SLOWEST.get(), k_PCURLCLOSEPOLICY_SLOWEST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_ABORTED_BY_CALLBACK.get(), k_PCURLE_ABORTED_BY_CALLBACK
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_BAD_CALLING_ORDER.get(), k_PCURLE_BAD_CALLING_ORDER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_BAD_CONTENT_ENCODING.get(), k_PCURLE_BAD_CONTENT_ENCODING
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_BAD_FUNCTION_ARGUMENT.get(), k_PCURLE_BAD_FUNCTION_ARGUMENT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_BAD_PASSWORD_ENTERED.get(), k_PCURLE_BAD_PASSWORD_ENTERED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_COULDNT_CONNECT.get(), k_PCURLE_COULDNT_CONNECT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_COULDNT_RESOLVE_HOST.get(), k_PCURLE_COULDNT_RESOLVE_HOST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_COULDNT_RESOLVE_PROXY.get(), k_PCURLE_COULDNT_RESOLVE_PROXY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FAILED_INIT.get(), k_PCURLE_FAILED_INIT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FILESIZE_EXCEEDED.get(), k_PCURLE_FILESIZE_EXCEEDED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FILE_COULDNT_READ_FILE.get(), k_PCURLE_FILE_COULDNT_READ_FILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_ACCESS_DENIED.get(), k_PCURLE_FTP_ACCESS_DENIED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_BAD_DOWNLOAD_RESUME.get(), k_PCURLE_FTP_BAD_DOWNLOAD_RESUME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_CANT_GET_HOST.get(), k_PCURLE_FTP_CANT_GET_HOST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_CANT_RECONNECT.get(), k_PCURLE_FTP_CANT_RECONNECT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_COULDNT_GET_SIZE.get(), k_PCURLE_FTP_COULDNT_GET_SIZE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_COULDNT_RETR_FILE.get(), k_PCURLE_FTP_COULDNT_RETR_FILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_COULDNT_SET_ASCII.get(), k_PCURLE_FTP_COULDNT_SET_ASCII
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_COULDNT_SET_BINARY.get(), k_PCURLE_FTP_COULDNT_SET_BINARY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_COULDNT_STOR_FILE.get(), k_PCURLE_FTP_COULDNT_STOR_FILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_COULDNT_USE_REST.get(), k_PCURLE_FTP_COULDNT_USE_REST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_PORT_FAILED.get(), k_PCURLE_FTP_PORT_FAILED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_QUOTE_ERROR.get(), k_PCURLE_FTP_QUOTE_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_SSL_FAILED.get(), k_PCURLE_FTP_SSL_FAILED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_USER_PASSWORD_INCORRECT.get(),
      k_PCURLE_FTP_USER_PASSWORD_INCORRECT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_WEIRD_227_FORMAT.get(), k_PCURLE_FTP_WEIRD_227_FORMAT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_WEIRD_PASS_REPLY.get(), k_PCURLE_FTP_WEIRD_PASS_REPLY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_WEIRD_PASV_REPLY.get(), k_PCURLE_FTP_WEIRD_PASV_REPLY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_WEIRD_SERVER_REPLY.get(), k_PCURLE_FTP_WEIRD_SERVER_REPLY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_WEIRD_USER_REPLY.get(), k_PCURLE_FTP_WEIRD_USER_REPLY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FTP_WRITE_ERROR.get(), k_PCURLE_FTP_WRITE_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_FUNCTION_NOT_FOUND.get(), k_PCURLE_FUNCTION_NOT_FOUND
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_GOT_NOTHING.get(), k_PCURLE_GOT_NOTHING
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_HTTP_NOT_FOUND.get(), k_PCURLE_HTTP_NOT_FOUND
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_HTTP_PORT_FAILED.get(), k_PCURLE_HTTP_PORT_FAILED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_HTTP_POST_ERROR.get(), k_PCURLE_HTTP_POST_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_HTTP_RANGE_ERROR.get(), k_PCURLE_HTTP_RANGE_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_LDAP_CANNOT_BIND.get(), k_PCURLE_LDAP_CANNOT_BIND
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_LDAP_INVALID_URL.get(), k_PCURLE_LDAP_INVALID_URL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_LDAP_SEARCH_FAILED.get(), k_PCURLE_LDAP_SEARCH_FAILED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_LIBRARY_NOT_FOUND.get(), k_PCURLE_LIBRARY_NOT_FOUND
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_MALFORMAT_USER.get(), k_PCURLE_MALFORMAT_USER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_OBSOLETE.get(), k_PCURLE_OBSOLETE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_OK.get(), k_PCURLE_OK
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_OPERATION_TIMEDOUT.get(), k_PCURLE_OPERATION_TIMEOUTED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_OPERATION_TIMEOUTED.get(), k_PCURLE_OPERATION_TIMEOUTED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_OUT_OF_MEMORY.get(), k_PCURLE_OUT_OF_MEMORY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_PARTIAL_FILE.get(), k_PCURLE_PARTIAL_FILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_READ_ERROR.get(), k_PCURLE_READ_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_RECV_ERROR.get(), k_PCURLE_RECV_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SEND_ERROR.get(), k_PCURLE_SEND_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SHARE_IN_USE.get(), k_PCURLE_SHARE_IN_USE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SSL_CACERT.get(), k_PCURLE_SSL_CACERT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SSL_CERTPROBLEM.get(), k_PCURLE_SSL_CERTPROBLEM
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SSL_CIPHER.get(), k_PCURLE_SSL_CIPHER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SSL_CONNECT_ERROR.get(), k_PCURLE_SSL_CONNECT_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SSL_ENGINE_NOTFOUND.get(), k_PCURLE_SSL_ENGINE_NOTFOUND
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SSL_ENGINE_SETFAILED.get(), k_PCURLE_SSL_ENGINE_SETFAILED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_SSL_PEER_CERTIFICATE.get(), k_PCURLE_SSL_PEER_CERTIFICATE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_TELNET_OPTION_SYNTAX.get(), k_PCURLE_TELNET_OPTION_SYNTAX
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_TOO_MANY_REDIRECTS.get(), k_PCURLE_TOO_MANY_REDIRECTS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_UNKNOWN_TELNET_OPTION.get(), k_PCURLE_UNKNOWN_TELNET_OPTION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_UNSUPPORTED_PROTOCOL.get(), k_PCURLE_UNSUPPORTED_PROTOCOL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_URL_MALFORMAT.get(), k_PCURLE_URL_MALFORMAT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_URL_MALFORMAT_USER.get(), k_PCURLE_URL_MALFORMAT_USER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLE_WRITE_ERROR.get(), k_PCURLE_WRITE_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLFTPAUTH_DEFAULT.get(), k_PCURLFTPAUTH_DEFAULT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLFTPAUTH_SSL.get(), k_PCURLFTPAUTH_SSL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLFTPAUTH_TLS.get(), k_PCURLFTPAUTH_TLS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLFTPSSL_ALL.get(), k_PCURLFTPSSL_ALL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLFTPSSL_CONTROL.get(), k_PCURLFTPSSL_CONTROL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLFTPSSL_NONE.get(), k_PCURLFTPSSL_NONE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLFTPSSL_TRY.get(), k_PCURLFTPSSL_TRY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_CONNECT_TIME.get(), k_PCURLINFO_CONNECT_TIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_CONTENT_LENGTH_DOWNLOAD.get(),
      k_PCURLINFO_CONTENT_LENGTH_DOWNLOAD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_CONTENT_LENGTH_UPLOAD.get(), k_PCURLINFO_CONTENT_LENGTH_UPLOAD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_CONTENT_TYPE.get(), k_PCURLINFO_CONTENT_TYPE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_EFFECTIVE_URL.get(), k_PCURLINFO_EFFECTIVE_URL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_FILETIME.get(), k_PCURLINFO_FILETIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_HEADER_OUT.get(), k_PCURLINFO_HEADER_OUT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_HEADER_SIZE.get(), k_PCURLINFO_HEADER_SIZE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_HTTP_CODE.get(), k_PCURLINFO_HTTP_CODE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_NAMELOOKUP_TIME.get(), k_PCURLINFO_NAMELOOKUP_TIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_PRETRANSFER_TIME.get(), k_PCURLINFO_PRETRANSFER_TIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_PRIVATE.get(), k_PCURLINFO_PRIVATE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_REDIRECT_COUNT.get(), k_PCURLINFO_REDIRECT_COUNT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_REDIRECT_TIME.get(), k_PCURLINFO_REDIRECT_TIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_REQUEST_SIZE.get(), k_PCURLINFO_REQUEST_SIZE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_SIZE_DOWNLOAD.get(), k_PCURLINFO_SIZE_DOWNLOAD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_SIZE_UPLOAD.get(), k_PCURLINFO_SIZE_UPLOAD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_SPEED_DOWNLOAD.get(), k_PCURLINFO_SPEED_DOWNLOAD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_SPEED_UPLOAD.get(), k_PCURLINFO_SPEED_UPLOAD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_SSL_VERIFYRESULT.get(), k_PCURLINFO_SSL_VERIFYRESULT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_STARTTRANSFER_TIME.get(), k_PCURLINFO_STARTTRANSFER_TIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLINFO_TOTAL_TIME.get(), k_PCURLINFO_TOTAL_TIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLMSG_DONE.get(), k_PCURLMSG_DONE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLM_BAD_EASY_HANDLE.get(), k_PCURLM_BAD_EASY_HANDLE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLM_BAD_HANDLE.get(), k_PCURLM_BAD_HANDLE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLM_CALL_MULTI_PERFORM.get(), k_PCURLM_CALL_MULTI_PERFORM
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLM_INTERNAL_ERROR.get(), k_PCURLM_INTERNAL_ERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLM_OK.get(), k_PCURLM_OK
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLM_OUT_OF_MEMORY.get(), k_PCURLM_OUT_OF_MEMORY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_AUTOREFERER.get(), k_PCURLOPT_AUTOREFERER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_BINARYTRANSFER.get(), k_PCURLOPT_BINARYTRANSFER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_BUFFERSIZE.get(), k_PCURLOPT_BUFFERSIZE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_CAINFO.get(), k_PCURLOPT_CAINFO
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_CAPATH.get(), k_PCURLOPT_CAPATH
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_CLOSEPOLICY.get(), k_PCURLOPT_CLOSEPOLICY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_CONNECTTIMEOUT.get(), k_PCURLOPT_CONNECTTIMEOUT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_COOKIE.get(), k_PCURLOPT_COOKIE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_COOKIEFILE.get(), k_PCURLOPT_COOKIEFILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_COOKIEJAR.get(), k_PCURLOPT_COOKIEJAR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_COOKIESESSION.get(), k_PCURLOPT_COOKIESESSION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_CRLF.get(), k_PCURLOPT_CRLF
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_CUSTOMREQUEST.get(), k_PCURLOPT_CUSTOMREQUEST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_DNS_CACHE_TIMEOUT.get(), k_PCURLOPT_DNS_CACHE_TIMEOUT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_DNS_USE_GLOBAL_CACHE.get(), k_PCURLOPT_DNS_USE_GLOBAL_CACHE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_EGDSOCKET.get(), k_PCURLOPT_EGDSOCKET
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_ENCODING.get(), k_PCURLOPT_ENCODING
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FAILONERROR.get(), k_PCURLOPT_FAILONERROR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FILE.get(), k_PCURLOPT_FILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FILETIME.get(), k_PCURLOPT_FILETIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FOLLOWLOCATION.get(), k_PCURLOPT_FOLLOWLOCATION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FORBID_REUSE.get(), k_PCURLOPT_FORBID_REUSE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FRESH_CONNECT.get(), k_PCURLOPT_FRESH_CONNECT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FTPAPPEND.get(), k_PCURLOPT_FTPAPPEND
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FTPLISTONLY.get(), k_PCURLOPT_FTPLISTONLY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FTPPORT.get(), k_PCURLOPT_FTPPORT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FTPSSLAUTH.get(), k_PCURLOPT_FTPSSLAUTH
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FTP_CREATE_MISSING_DIRS.get(), k_PCURLOPT_FTP_CREATE_MISSING_DIRS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FTP_SSL.get(), k_PCURLOPT_FTP_SSL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FTP_USE_EPRT.get(), k_PCURLOPT_FTP_USE_EPRT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FTP_USE_EPSV.get(), k_PCURLOPT_FTP_USE_EPSV
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_HEADER.get(), k_PCURLOPT_HEADER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_HEADERFUNCTION.get(), k_PCURLOPT_HEADERFUNCTION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_HTTP200ALIASES.get(), k_PCURLOPT_HTTP200ALIASES
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_HTTPAUTH.get(), k_PCURLOPT_HTTPAUTH
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_HTTPGET.get(), k_PCURLOPT_HTTPGET
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_HTTPHEADER.get(), k_PCURLOPT_HTTPHEADER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_HTTPPROXYTUNNEL.get(), k_PCURLOPT_HTTPPROXYTUNNEL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_HTTP_VERSION.get(), k_PCURLOPT_HTTP_VERSION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_INFILE.get(), k_PCURLOPT_INFILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_INFILESIZE.get(), k_PCURLOPT_INFILESIZE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_INTERFACE.get(), k_PCURLOPT_INTERFACE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_IPRESOLVE.get(), k_PCURLOPT_IPRESOLVE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_KRB4LEVEL.get(), k_PCURLOPT_KRB4LEVEL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_LOW_SPEED_LIMIT.get(), k_PCURLOPT_LOW_SPEED_LIMIT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_LOW_SPEED_TIME.get(), k_PCURLOPT_LOW_SPEED_TIME
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_MAXCONNECTS.get(), k_PCURLOPT_MAXCONNECTS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_MAXREDIRS.get(), k_PCURLOPT_MAXREDIRS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_MUTE.get(), k_PCURLOPT_MUTE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_NETRC.get(), k_PCURLOPT_NETRC
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_NOBODY.get(), k_PCURLOPT_NOBODY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_NOPROGRESS.get(), k_PCURLOPT_NOPROGRESS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_NOSIGNAL.get(), k_PCURLOPT_NOSIGNAL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PASSWDFUNCTION.get(), k_PCURLOPT_PASSWDFUNCTION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PORT.get(), k_PCURLOPT_PORT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_POST.get(), k_PCURLOPT_POST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_POSTFIELDS.get(), k_PCURLOPT_POSTFIELDS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_POSTREDIR.get(), k_PCURLOPT_POSTREDIR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PROTOCOLS.get(), k_PCURLOPT_PROTOCOLS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_REDIR_PROTOCOLS.get(), k_PCURLOPT_REDIR_PROTOCOLS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_POSTQUOTE.get(), k_PCURLOPT_POSTQUOTE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PRIVATE.get(), k_PCURLOPT_PRIVATE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PROGRESSFUNCTION.get(), k_PCURLOPT_PROGRESSFUNCTION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PROXY.get(), k_PCURLOPT_PROXY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PROXYAUTH.get(), k_PCURLOPT_PROXYAUTH
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PROXYPORT.get(), k_PCURLOPT_PROXYPORT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PROXYTYPE.get(), k_PCURLOPT_PROXYTYPE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PROXYUSERPWD.get(), k_PCURLOPT_PROXYUSERPWD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_PUT.get(), k_PCURLOPT_PUT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_QUOTE.get(), k_PCURLOPT_QUOTE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_RANDOM_FILE.get(), k_PCURLOPT_RANDOM_FILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_RANGE.get(), k_PCURLOPT_RANGE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_READDATA.get(), k_PCURLOPT_READDATA
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_READFUNCTION.get(), k_PCURLOPT_READFUNCTION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_REFERER.get(), k_PCURLOPT_REFERER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_RESOLVE.get(), k_PCURLOPT_RESOLVE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_RESUME_FROM.get(), k_PCURLOPT_RESUME_FROM
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_RETURNTRANSFER.get(), k_PCURLOPT_RETURNTRANSFER
    );
#ifdef FACEBOOK
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SERVICE_NAME.get(), k_PCURLOPT_SERVICE_NAME
    );
#endif
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLCERT.get(), k_PCURLOPT_SSLCERT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLCERTPASSWD.get(), k_PCURLOPT_SSLCERTPASSWD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLCERTTYPE.get(), k_PCURLOPT_SSLCERTTYPE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLENGINE.get(), k_PCURLOPT_SSLENGINE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLENGINE_DEFAULT.get(), k_PCURLOPT_SSLENGINE_DEFAULT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLKEY.get(), k_PCURLOPT_SSLKEY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLKEYPASSWD.get(), k_PCURLOPT_SSLKEYPASSWD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLKEYTYPE.get(), k_PCURLOPT_SSLKEYTYPE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSLVERSION.get(), k_PCURLOPT_SSLVERSION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSL_CIPHER_LIST.get(), k_PCURLOPT_SSL_CIPHER_LIST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSL_VERIFYHOST.get(), k_PCURLOPT_SSL_VERIFYHOST
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_SSL_VERIFYPEER.get(), k_PCURLOPT_SSL_VERIFYPEER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_STDERR.get(), k_PCURLOPT_STDERR
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_TCP_NODELAY.get(), k_PCURLOPT_TCP_NODELAY
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_TIMECONDITION.get(), k_PCURLOPT_TIMECONDITION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_TIMEOUT.get(), k_PCURLOPT_TIMEOUT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_TIMEVALUE.get(), k_PCURLOPT_TIMEVALUE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_TRANSFERTEXT.get(), k_PCURLOPT_TRANSFERTEXT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_UNRESTRICTED_AUTH.get(), k_PCURLOPT_UNRESTRICTED_AUTH
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_UPLOAD.get(), k_PCURLOPT_UPLOAD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_URL.get(), k_PCURLOPT_URL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_USERAGENT.get(), k_PCURLOPT_USERAGENT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_USERPWD.get(), k_PCURLOPT_USERPWD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_VERBOSE.get(), k_PCURLOPT_VERBOSE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_WRITEFUNCTION.get(), k_PCURLOPT_WRITEFUNCTION
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_WRITEHEADER.get(), k_PCURLOPT_WRITEHEADER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FB_TLS_VER_MAX.get(), k_PCURLOPT_FB_TLS_VER_MAX
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FB_TLS_VER_MAX_NONE.get(), k_PCURLOPT_FB_TLS_VER_MAX_NONE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FB_TLS_VER_MAX_1_1.get(), k_PCURLOPT_FB_TLS_VER_MAX_1_1
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FB_TLS_VER_MAX_1_0.get(), k_PCURLOPT_FB_TLS_VER_MAX_1_0
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLOPT_FB_TLS_CIPHER_SPEC.get(), k_PCURLOPT_FB_TLS_CIPHER_SPEC
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROXY_HTTP.get(), k_PCURLPROXY_HTTP
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROXY_SOCKS5.get(), k_PCURLPROXY_SOCKS5
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLVERSION_NOW.get(), k_PCURLVERSION_NOW
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_HTTP_VERSION_1_0.get(), k_PCURL_HTTP_VERSION_1_0
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_HTTP_VERSION_1_1.get(), k_PCURL_HTTP_VERSION_1_1
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_HTTP_VERSION_NONE.get(), k_PCURL_HTTP_VERSION_NONE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_IPRESOLVE_V4.get(), k_PCURL_IPRESOLVE_V4
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_IPRESOLVE_V6.get(), k_PCURL_IPRESOLVE_V6
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_IPRESOLVE_WHATEVER.get(), k_PCURL_IPRESOLVE_WHATEVER
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_NETRC_IGNORED.get(), k_PCURL_NETRC_IGNORED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_NETRC_OPTIONAL.get(), k_PCURL_NETRC_OPTIONAL
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_NETRC_REQUIRED.get(), k_PCURL_NETRC_REQUIRED
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_TIMECOND_IFMODSINCE.get(), k_PCURL_TIMECOND_IFMODSINCE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_TIMECOND_IFUNMODSINCE.get(), k_PCURL_TIMECOND_IFUNMODSINCE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_TIMECOND_LASTMOD.get(), k_PCURL_TIMECOND_LASTMOD
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_VERSION_IPV6.get(), k_PCURL_VERSION_IPV6
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_VERSION_KERBEROS4.get(), k_PCURL_VERSION_KERBEROS4
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_VERSION_LIBZ.get(), k_PCURL_VERSION_LIBZ
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURL_VERSION_SSL.get(), k_PCURL_VERSION_SSL
    );

    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_HTTP.get(), k_PCURLPROTO_HTTP
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_HTTPS.get(), k_PCURLPROTO_HTTPS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_FTP.get(), k_PCURLPROTO_FTP
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_FTPS.get(), k_PCURLPROTO_FTPS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_SCP.get(), k_PCURLPROTO_SCP
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_SFTP.get(), k_PCURLPROTO_SFTP
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_TELNET.get(), k_PCURLPROTO_TELNET
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_LDAP.get(), k_PCURLPROTO_LDAP
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_LDAPS.get(), k_PCURLPROTO_LDAPS
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_DICT.get(), k_PCURLPROTO_DICT
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_FILE.get(), k_PCURLPROTO_FILE
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_TFTP.get(), k_PCURLPROTO_TFTP
    );
    Native::registerConstant<KindOfInt64>(
      s_PCURLPROTO_ALL.get(), k_PCURLPROTO_ALL
    );

    HHVM_FE(pcurl_init);
    HHVM_FE(pcurl_init_pooled);
    HHVM_FE(pcurl_copy_handle);
    HHVM_FE(pcurl_version);
    HHVM_FE(pcurl_setopt);
    HHVM_FE(pcurl_setopt_array);
    HHVM_FE(fb_pcurl_getopt);
    HHVM_FE(pcurl_exec);
    HHVM_FE(pcurl_getinfo);
    HHVM_FE(pcurl_errno);
    HHVM_FE(pcurl_error);
    HHVM_FE(pcurl_close);
    HHVM_FE(pcurl_reset);
    HHVM_FE(pcurl_multi_init);
    HHVM_FE(pcurl_multi_add_handle);
    HHVM_FE(pcurl_multi_remove_handle);
    HHVM_FE(pcurl_multi_exec);
    HHVM_FE(pcurl_multi_select);
    HHVM_FE(pcurl_multi_await);
    HHVM_FE(pcurl_multi_getcontent);
    HHVM_FE(fb_pcurl_multi_fdset);
    HHVM_FE(pcurl_multi_info_read);
    HHVM_FE(pcurl_multi_close);
    HHVM_FE(pcurl_strerror);

    Extension* ext = ExtensionRegistry::get("pcurl");
    assert(ext);

    IniSetting::Bind(ext, IniSetting::PHP_INI_SYSTEM, "pcurl.namedPools",
      "", &s_namedPools);
    if (s_namedPools.length() > 0) {

      // split on commas, search and bind ini settings for each pool
      std::vector<string> pools;
      boost::split(pools, s_namedPools, boost::is_any_of(","));

      for (std::string poolname: pools) {
        if (poolname.length() == 0) { continue; }

        // get the user-entered settings for this pool, if there are any
        std::string poolSizeIni = "pcurl.namedPools." + poolname + ".size";
        std::string reuseLimitIni =
          "pcurl.namedPools." + poolname + ".reuseLimit";
        std::string getTimeoutIni =
          "pcurl.namedPools." + poolname + ".connGetTimeout";

        IniSetting::Bind(ext, IniSetting::PHP_INI_SYSTEM, poolSizeIni,
            "5", &s_poolSize);
        IniSetting::Bind(ext, IniSetting::PHP_INI_SYSTEM, reuseLimitIni,
            "100", &s_reuseLimit);
        IniSetting::Bind(ext, IniSetting::PHP_INI_SYSTEM, getTimeoutIni,
            "5000", &s_getTimeout);

        PCurlHandlePool *hp =
          new PCurlHandlePool(s_poolSize, s_getTimeout, s_reuseLimit);
        PCurlHandlePool::namedPools[poolname] = hp;
      }
    }

    loadSystemlib();
  }

  void moduleShutdown() override {
    for (auto const kvItr: PCurlHandlePool::namedPools) {
      delete kvItr.second;
    }
    /* CUSTOM_START */
    hostSocketFdPool->clean();
    hostSocketFdPool.reset();
    //_LOG("extension pcurl: shut down");
    /* CUSTOM_END */
  }

} s_pcurl_extension;

HHVM_GET_MODULE(pcurl);

}
