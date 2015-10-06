<?hh

namespace {

//<<__Native>>
//function pcurl_pool_stats(): string;
//
//<<__Native>>
//function pcurl_pool_stats_array(): Array;
//
//<<__Native>>
//function pcurl_pool_reset(): bool;
//
///**
// * Close a cURL session
// *
// * @param resource $ch -
// *
// * @return void -
// */
//<<__Native>>
//function pcurl_close(resource $ch): ?bool;
//
///**
// * Copy a cURL handle along with all of its preferences
// *
// * @param resource $ch -
// *
// * @return resource - Returns a new cURL handle.
// */
//<<__Native>>
//function pcurl_copy_handle(resource $ch): mixed;
//
///**
// * Return the last error number
// *
// * @param resource $ch -
// *
// * @return int - Returns the error number or 0 (zero) if no error
// *   occurred.
// */
//<<__Native>>
//function pcurl_errno(resource $ch): mixed;
//
///**
// * Return a string containing the last error for the current session
// *
// * @param resource $ch -
// *
// * @return string - Returns the error message or '' (the empty string) if
// *   no error occurred.
// */
//<<__Native>>
//function pcurl_error(resource $ch): mixed;
//
///**
// * Returns a string description of a cURL error code
// *
// * @param int $errno - a pcurl error code, e.g. returned by pcurl_errno()
// *
// * @return string - Returns a string description of a cURL error code
// */
//<<__Native>>
//function pcurl_strerror(int $errno): string;
//
///**
// * Perform a cURL session
// *
// * @param resource $ch -
// *
// * @return mixed - However, if the PCURLOPT_RETURNTRANSFER option is set,
// *   it will return the result on success, FALSE on failure.
// */
//<<__Native>>
//function pcurl_exec(resource $ch): mixed;
//
///**
// * Get information regarding a specific transfer
// *
// * @param resource $ch -
// * @param int $opt - This may be one of the following constants:
// *   PCURLINFO_EFFECTIVE_URL - Last effective URL     PCURLINFO_HTTP_CODE -
// *   Last received HTTP code     PCURLINFO_FILETIME - Remote time of the
// *   retrieved document, if -1 is returned the time of the document is
// *   unknown     PCURLINFO_TOTAL_TIME - Total transaction time in seconds
// *   for last transfer     PCURLINFO_NAMELOOKUP_TIME - Time in seconds until
// *   name resolving was complete     PCURLINFO_CONNECT_TIME - Time in
// *   seconds it took to establish the connection
// *   PCURLINFO_PRETRANSFER_TIME - Time in seconds from start until just
// *   before file transfer begins     PCURLINFO_STARTTRANSFER_TIME - Time in
// *   seconds until the first byte is about to be transferred
// *   PCURLINFO_REDIRECT_COUNT - Number of redirects
// *   PCURLINFO_REDIRECT_TIME - Time in seconds of all redirection steps
// *   before final transaction was started     PCURLINFO_SIZE_UPLOAD - Total
// *   number of bytes uploaded     PCURLINFO_SIZE_DOWNLOAD - Total number of
// *   bytes downloaded     PCURLINFO_SPEED_DOWNLOAD - Average download speed
// *      PCURLINFO_SPEED_UPLOAD - Average upload speed
// *   PCURLINFO_HEADER_SIZE - Total size of all headers received
// *   PCURLINFO_HEADER_OUT - The request string sent. For this to work, add
// *   the PCURLINFO_HEADER_OUT option to the handle by calling pcurl_setopt()
// *      PCURLINFO_REQUEST_SIZE - Total size of issued requests, currently
// *   only for HTTP requests     PCURLINFO_SSL_VERIFYRESULT - Result of SSL
// *   certification verification requested by setting PCURLOPT_SSL_VERIFYPEER
// *       PCURLINFO_CONTENT_LENGTH_DOWNLOAD - content-length of download,
// *   read from Content-Length: field     PCURLINFO_CONTENT_LENGTH_UPLOAD -
// *   Specified size of upload     PCURLINFO_CONTENT_TYPE - Content-Type: of
// *   the requested document, NULL indicates server did not send valid
// *   Content-Type: header
// *
// * @return mixed - If opt is given, returns its value. Otherwise, returns
// *   an associative array with the following elements (which correspond to
// *   opt), or FALSE on failure:    "url"     "content_type"     "http_code"
// *       "header_size"     "request_size"     "filetime"
// *   "ssl_verify_result"     "redirect_count"     "total_time"
// *   "namelookup_time"     "connect_time"     "pretransfer_time"
// *   "size_upload"     "size_download"     "speed_download"
// *   "speed_upload"     "download_content_length"
// *   "upload_content_length"     "starttransfer_time"     "redirect_time"
// *     "certinfo"     "request_header" (This is only set if the
// *   PCURLINFO_HEADER_OUT is set by a previous call to pcurl_setopt())
// */
//<<__Native>>
//function pcurl_getinfo(resource $ch,
//                      int $opt = 0): mixed;
//
///**
// * Initialize a cURL session
// *
// * @param string $url - If provided, the PCURLOPT_URL option will be set
// *   to its value. You can manually set this using the pcurl_setopt()
// *   function.    The file protocol is disabled by cURL if open_basedir is
// *   set.
// *
// * @return resource - Returns a cURL handle on success, FALSE on errors.
// */
//<<__Native>>
//function pcurl_init(?string $url = null): mixed;
//
//
///**
// * Initialize a cURL session using a pooled pcurl handle. When this resource
// * is garbage collected, the pcurl handle will be saved for reuse later.
// * Pooled pcurl handles persist between requests.
// *
// * @param string $poolName - The name of the connection pool to use.
// *  Named connection pools are initialized via the 'pcurl.namedPools' ini
// *  setting, which is a comma separated list of named pools to create.
// * @param string $url - If provided, the PCURLOPT_URL option will be set
// *   to its value. You can manually set this using the pcurl_setopt()
// *   function.    The file protocol is disabled by cURL if open_basedir is
// *   set.
// *
// * @return resource - Returns a cURL handle on success, FALSE on errors.
// */
//<<__Native, __HipHopSpecific>>
//function pcurl_init_pooled(string $poolName, ?string $url = null): mixed;
//
///**
// * Add a normal cURL handle to a cURL multi handle
// *
// * @param resource $mh -
// * @param resource $ch -
// *
// * @return int - Returns 0 on success, or one of the PCURLM_XXX errors
// *   code.
// */
//<<__Native>>
//function pcurl_multi_add_handle(resource $mh,
//                               resource $ch): ?int;
//
///**
// * Close a set of cURL handles
// *
// * @param resource $mh -
// *
// * @return void -
// */
//<<__Native>>
//function pcurl_multi_close(resource $mh): mixed;
//
///**
// * Run the sub-connections of the current cURL handle
// *
// * @param resource $mh -
// * @param int $still_running - A reference to a flag to tell whether the
// *   operations are still running.
// *
// * @return int - A cURL code defined in the cURL Predefined Constants.
// *   This only returns errors regarding the whole multi stack. There might
// *   still have occurred problems on individual transfers even when this
// *   function returns PCURLM_OK.
// */
//<<__Native>>
//function pcurl_multi_exec(resource $mh,
//                         mixed &$still_running): ?int;
//
///**
// * Return the content of a cURL handle if  is set
// *
// * @param resource $ch -
// *
// * @return string - Return the content of a cURL handle if
// *   PCURLOPT_RETURNTRANSFER is set.
// */
//<<__Native>>
//function pcurl_multi_getcontent(resource $ch): ?string;
//
///**
// * Get information about the current transfers
// *
// * @param resource $mh -
// * @param int $msgs_in_queue - Number of messages that are still in the
// *   queue
// *
// * @return array - On success, returns an associative array for the
// *   message, FALSE on failure.    Contents of the returned array    Key:
// *   Value:     msg The PCURLMSG_DONE constant. Other return values are
// *   currently not available.   result One of the PCURLE_* constants. If
// *   everything is OK, the PCURLE_OK will be the result.   handle Resource
// *   of type pcurl indicates the handle which it concerns.
// */
//<<__Native>>
//function pcurl_multi_info_read(resource $mh,
//                              mixed &$msgs_in_queue = NULL): mixed;
//
///**
// * Returns a new cURL multi handle
// *
// * @return resource - Returns a cURL multi handle resource on success,
// *   FALSE on failure.
// */
//<<__Native>>
//function pcurl_multi_init(): resource;
//
///**
// * Remove a multi handle from a set of cURL handles
// *
// * @param resource $mh -
// * @param resource $ch -
// *
// * @return int - Returns 0 on success, or one of the PCURLM_XXX error
// *   codes.
// */
//<<__Native>>
//function pcurl_multi_remove_handle(resource $mh,
//                                  resource $ch): ?int;
//
///**
// * Wait for activity on any pcurl_multi connection
// *
// * @param resource $mh -
// * @param float $timeout - Time, in seconds, to wait for a response.
// *
// * @return int - On success, returns the number of descriptors contained
// *   in the descriptor sets. On failure, this function will return -1 on a
// *   select failure or timeout (from the underlying select system call).
// */
//<<__Native>>
//function pcurl_multi_select(resource $mh,
//                           float $timeout = 1.0): ?int;
//
//<<__Native>>
//function pcurl_multi_await(resource $mh,
//                          float $timeout = 1.0): Awaitable<int>;
//
///**
// * Set multiple options for a cURL transfer
// *
// * @param resource $ch -
// * @param array $options - An array specifying which options to set and
// *   their values. The keys should be valid pcurl_setopt() constants or
// *   their integer equivalents.
// *
// * @return bool - Returns TRUE if all options were successfully set. If
// *   an option could not be successfully set, FALSE is immediately
// *   returned, ignoring any future options in the options array.
// */
//<<__Native>>
//function pcurl_setopt_array(resource $ch,
//                           array $options): bool;
//
///**
// * Set an option for a cURL transfer
// *
// * @param resource $ch -
// * @param int $option - The PCURLOPT_XXX option to set.
// * @param mixed $value - The value to be set on option.
// *
// * @return bool -
// */
//<<__Native>>
//function pcurl_setopt(resource $ch,
//                     int $option,
//                     mixed $value): bool;
//
///**
// * Gets cURL version information
// *
// * @param int $age -
// *
// * @return array - Returns an associative array with the following
// *   elements:     Indice Value description     version_number cURL 24 bit
// *   version number   version cURL version number, as a string
// *   ssl_version_number OpenSSL 24 bit version number   ssl_version OpenSSL
// *   version number, as a string   libz_version zlib version number, as a
// *   string   host Information about the host where cURL was built   age
// *   features A bitmask of the PCURL_VERSION_XXX constants   protocols An
// *   array of protocols names supported by cURL
// */
//<<__Native>>
//function pcurl_version(int $age = PCURLVERSION_NOW): mixed;
//
//<<__Native>>
//function pcurl_reset(resource $ch): void;
//
///**
// * Gets options on the given cURL session handle.
// *
// * @param resource $ch - A cURL handle returned by pcurl_init().
// * @param int $opt     - This should be one of the PCURLOPT_* values.
// *
// * @return mixed - If opt is given, returns its value. Otherwise, returns an
// *    associative array.
// */
//<<__Native, __HipHopSpecific>>
//function fb_pcurl_getopt(resource $ch, int $opt = 0): mixed;
//
///**
// * extracts file descriptor information from a multi handle.
// *
// * @param resource $mh         - A cURL multi handle returned by
// *     pcurl_multi_init().
// * @param array& $read_fd_set  - read set
// * @param array& $write_fd_set - write set
// * @param array& $exc_fd_set   - exception set
// * @param int& $max_fd         - If no file descriptors are set, $max_fd will
// *     contain -1. Otherwise it will contain the higher descriptor number.
// *
// * @return mixed - Returns 0 on success, or one of the PCURLM_XXX errors code.
// */
//<<__Native, __HipHopSpecific>>
//function fb_pcurl_multi_fdset(resource $mh, mixed &$read_fd_set,
//                             mixed &$write_fd_set, mixed &$exc_fd_set,
//                             ?int &$max_fd = null): mixed;

} // root namespace

namespace HH\Asio {

///**
// * Wind a pcurl handle through an awaitable loop to fetch the result
// *
// * @param mixed $urlOrHandle - An existing cURL handle or a URL as a string.
// *                           - String URLs will create a default cURL GET
// * @return Awaitable<string> - Awaitable handle yielding a string
// */
//async function pcurl_exec(mixed $urlOrHandle): Awaitable<string> {
//  if (is_string($urlOrHandle)) {
//    $ch = pcurl_init($urlOrHandle);
//  } else if (is_resource($urlOrHandle) &&
//             (get_resource_type($urlOrHandle) == "pcurl")) {
//    $ch = $urlOrHandle;
//  } else {
//    throw new Exception(__FUNCTION__." expects string of cURL handle");
//  }
//  pcurl_setopt($ch, PCURLOPT_RETURNTRANSFER, true);
//
//  $mh = pcurl_multi_init();
//  pcurl_multi_add_handle($mh, $ch);
//  $sleep_ms = 10;
//  do {
//    $active = 1;
//    do {
//      $status = pcurl_multi_exec($mh, $active);
//    } while ($status == PCURLM_CALL_MULTI_PERFORM);
//    if (!$active) break;
//    $select = await pcurl_multi_await($mh);
//    /* If cURL is built without ares support, DNS queries don't have a socket
//     * to wait on, so pcurl_multi_await() (and pcurl_select() in PHP5) will return
//     * -1, and polling is required.
//     */
//    if ($select == -1) {
//      await SleepWaitHandle::create($sleep_ms * 1000);
//      if ($sleep_ms < 1000) {
//        $sleep_ms *= 2;
//      }
//    } else {
//      $sleep_ms = 10;
//    }
//  } while ($status === PCURLM_OK);
//  $content = (string)pcurl_multi_getcontent($ch);
//  pcurl_multi_remove_handle($mh, $ch);
//  pcurl_multi_close($mh);
//  return $content;
//}

} // namespace HH\Asio
