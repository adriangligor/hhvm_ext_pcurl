# This project is deprecated! As the HHVM project evolves, the effort to keep PCURL in sync with their code has proven to be too high. At the same time our internal use-case has disappeared by rewriting critical parts of our software in a more appropriate language than PHP. This project will not be updated, the last supported HHVM version will stay 3.9.

# PCURL - HHVM persistent cURL

PCURL is an extension for [HHVM](https://github.com/facebook/hhvm) that mirrors the default cURL extension but allows TCP/IP sockets to be reused by a series of consecutive requests. This, combined with [HTTP persistent connections](http://en.wikipedia.org/wiki/HTTP_persistent_connection), enables opening a connection to a remote HTTP server and reusing it over longer periods of time. This extension is a simple fork of the actual [HHVM cURL extension](http://docs.hhvm.com/manual/en/ref.curl.php) and offers the same API with renamed function and constant names. Existing code needs to be changed in a trivial way in order to use PCURL, by renaming a couple of function calls and parameters.

## The Problem

The HHVM cURL extension offers out-of-the-box support for HTTP persistent connections. As long as you reuse the same cURL handle to send multiple requests to the same target server, the same HTTP connection is being used internally, instead of being closed and reopened on every request.

Due to PHP's lifecycle however, all socket connections are automatically closed at the end of your script. For a CLI script this will probably not be an issue, but for a server-side script that is called frequently, the overhead of closing and re-opening connections for every single call is considerable for both client and server, and increases response times.

The same problem is encountered when connecting to databases in PHP: opening and closing a connection to a database in every single request slows down response times considerably.

## The Solution

[The PHP PDO library uses persistent connections](http://php.net/manual/en/pdo.connections.php) to avoid opening fresh connections to the database for every request. These connections are kept open after requests end, and are transparently reused in later requests. Should a connection drop, it will be automatically renewed. A script doesn't need to be aware of this process, it just creates PDO objects with the appropriate connection string and persistent connections are automatically used behind the scenes.

PCURL applies the same principle to connections used by cURL. It overrides libcurl's connection creation and destruction process and caches connections inbetween use.

## Installation

This extension has been tested with HHVM 3.2 to 3.6 and is confirmed to work.

[Follow these instructions](https://github.com/facebook/hhvm/wiki/Prebuilt%20Packages%20for%20HHVM) to install **HHVM 3.2+** on your distro of choice. You'll also need the corresponding **development package**, which contains the `hphpize` tool and C++ headers for extension compilation, and should also pull in **GCC 4.8+** and **cmake** automatically.

Some of the following steps apply only to Ubuntu, if you use another distribution you may need to use different locations and another package manager.

**Note**: the Ubuntu package `hhvm-dev` 3.2 doesn't set the executable flag on the `hphpize` binary, so you'll need to fix it:

    $ sudo apt-get install hhvm-dev
    $ sudo chmod a+x /usr/bin/hphpize

Now the source for the PCURL extension can be compiled:

    $ cd ext_pcurl
    $ hphpize && cmake . && make

Install the compiled extension to a directory of your choice, for example:
   
    $ sudo cp pcurl.so /usr/lib/hhvm/ext/
    
Edit your `/etc/hhvm/config.hdf` file and add a reference to the extension:

    DynamicExtensionPath = /usr/lib/hhvm/ext/
    DynamicExtensions {
        pcurl = pcurl.so
        # myexample = myexample.so
    }

**Note**: on Ubuntu, HHVM doesn't read `/etc/hhvm/config.hdf` by default. The file needs to be created first, and then to be enabled manually by editing `/etc/default/hhvm` and setting:

    ADDITIONAL_ARGS="-c /etc/hhvm/config.hdf"

Restarting HHVM will complete the installation:

    $ sudo /etc/init.d/hhvm restart

## Usage

All functions that are normally prefixed `curl_*` with the cURL extension, are duplicated and prefixed `pcurl_*`. All constants called `CURL*` follow the same pattern and are duplicated as `PCURL*`. **Don't intermix calls to the standard cURL extension and PCURL, and their constants!** Separate usage within the same script is perfectly fine though.

Example with the default cURL extension:

    <?php
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, "http://www.example.com/");
    curl_setopt($ch, CURLOPT_HEADER, 0);

    curl_exec($ch);

    curl_close($ch);
    ?>

Same example with PCURL:

    <?php
    $ch = pcurl_init();

    pcurl_setopt($ch, PCURLOPT_URL, "http://www.example.com/");
    pcurl_setopt($ch, PCURLOPT_HEADER, 0);

    pcurl_exec($ch);

    pcurl_close($ch);
    ?>

Closing the handle will only return it to the pool instead of closing it for real.

The PCURL extension's pool size is at most as large as the `ThreadCount` setting of your HHVM installation. PCURL manages a separate pool of connections for every host contacted, and automatically disposes of old entries.

### Additional Functions

**pcurl_pool_stats**

    string pcurl_pool_stats()

Returns an overview of the number of used and free sockets in each host connection pool as a string.

Example:

    <?php
    print(pcurl_pool_stats() . "\n");
    ?>

Output:

    sockets: my.host1.com:80: free: 1, taken: 0; my.host2.net:80: free: 1, taken: 0;

**pcurl_pool_stats_array**

Returns an overview of the number of used and free sockets in each host connection pool as an array.

Example:

    <?php
    print(pcurl_pool_stats() . "\n");
    ?>

Output:

    Array
    (
        [my.host1.com:80] => Array
            (
                [free] => 1
                [taken] => 0
            )
        [my.host2.net:80] => Array
            (
                [free] => 1
                [taken] => 0
            )
    )


**pcurl_pool_reset**

    bool pcurl_pool_reset()

Disposes of all the stalled connections held in all the host connection pools. Returns `true` if all pools are completely empty after usage. Connections that are still alive or in active use are not closed.

Example:

    <?php
    var_dump(pcurl_pool_reset());
    print(pcurl_pool_stats() . "\n");
    ?>

Output:

    bool(false)
    sockets: my.host1.com:80: free: 1, taken: 0; my.host2.net:80: free: 0, taken: 1;

## Practical Advice

In a previous version, this extension used to pool cURL handles instead of actual socket connections, since it was easier to implement. The cases where PCURL could be used efficiently were difficult to describe and users needed to monitor socket usage and know their scripts well. Also the pools needed to be periodically reset if there were periodical fluctuations. This section used to contain all kind of advice, but since then PCURL has changed to pool connections. The pool sizes are now automatically grown and shrinked with usage. Stale connections are automatically removed and new ones created on demand.

The only thing you need to keep in mind is that PCURL only makes sense if connections to the same host are reused faster than the server closes them. Otherwise there is no benefit over standard cURL.

You can check for socket usage with `netstat`:

    $ sudo netstat -an | awk '/tcp/ {print $6}' | sort | uniq -c
    1396 CLOSE_WAIT
       1 CLOSING
     858 ESTABLISHED
       1 FIN_WAIT1
      13 FIN_WAIT2
       1 LAST_ACK
       9 LISTEN
       3 SYN_SENT
     248 TIME_WAIT

A high number of CLOSE_WAIT connections means the server is closing connections, and PCURL hasn't come around removing them from the pool. There will always be CLOSE_WAIT connections, but their number should be far lower than this example.

A high number of TIME_WAIT connections means the the client (your script) is closing connections, and their specific host:port combination is kept reserved for a while by the kernel to avoid delayed network packets confusing fresh connections on the same host:port. If you see a high number on your server, you're probably not using PCURL in a place where you should, or that you infrequently connect to many different hosts, in which case PCURL cannot work efficiently.

A high number of ESTABLISHED connections means PCURL is working as intended, and has adapted to your high load. The number in the example above is very high, though.

## License

This code is based on the cURL extension included with HHVM and uses the [PHP license](./LICENSE.PHP) like the original. The included header files have been taken straight from the HHVM project and are under their original license.

## Authors

The PCURL extension has been brought to you by the authors of the original [HHVM cURL extension](https://github.com/facebook/hhvm) and the [MobFox](https://github.com/mobfox) team.

Contributors:

* [Adrian Gligor](https://github.com/adriangligor)
* [David Spitzer](https://github.com/dspitzer)
