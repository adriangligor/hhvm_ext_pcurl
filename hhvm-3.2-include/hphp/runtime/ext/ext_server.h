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

#ifndef incl_HPHP_EXT_SERVER_H_
#define incl_HPHP_EXT_SERVER_H_

// >>>>>> Generated by idl.php. Do NOT modify. <<<<<<

#include "hphp/runtime/base/base-includes.h"

namespace HPHP {
///////////////////////////////////////////////////////////////////////////////

extern const int64_t k_PAGELET_NOT_READY;
extern const int64_t k_PAGELET_READY;
extern const int64_t k_PAGELET_DONE;

enum PageletStatusType {
  PAGELET_NOT_READY,
  PAGELET_READY,
  PAGELET_DONE
};

///////////////////////////////////////////////////////////////////////////////

bool f_dangling_server_proxy_old_request();
bool f_pagelet_server_is_enabled();
Resource f_pagelet_server_task_start(const String& url, const Array& headers = null_array, const String& post_data = null_string, const Array& files = null_array);
int64_t f_pagelet_server_task_status(const Resource& task);
String f_pagelet_server_task_result(const Resource& task, VRefParam headers, VRefParam code, int64_t timeout_ms);
void f_pagelet_server_flush();
bool f_xbox_send_message(const String& msg, VRefParam ret, int64_t timeout_ms, const String& host = "localhost");
bool f_xbox_post_message(const String& msg, const String& host = "localhost");
Resource f_xbox_task_start(const String& message);
bool f_xbox_task_status(const Resource& task);
int64_t f_xbox_task_result(const Resource& task, int64_t timeout_ms, VRefParam ret);
Variant f_xbox_process_call_message(const String& msg);
int64_t f_xbox_get_thread_timeout();
void f_xbox_set_thread_timeout(int timeout);
void f_xbox_schedule_thread_reset();
int64_t f_xbox_get_thread_time();

///////////////////////////////////////////////////////////////////////////////
}

#endif // incl_HPHP_EXT_SERVER_H_
