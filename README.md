# PCURL - HHVM persistent cURL

PCURL is an extension for [HHVM](https://github.com/facebook/hhvm) that allows cURL handles to be reused by a series of consecutive requests. This, combined with [HTTP persistent connections](http://en.wikipedia.org/wiki/HTTP_persistent_connection), enables opening a connection to a remote HTTP server and reusing it over longer periods of time. This extension is a simple fork of the actual [HHVM cURL extension](http://docs.hhvm.com/manual/en/ref.curl.php) and offers the same API with renamed function and constant names. Existing code needs to be changed in a trivial way in order to use PCURL, by renaming a couple of function calls and parameters.

## The Problem

The HHVM cURL extension offers out-of-the-box support for HTTP persistent connections. As long as you reuse the same cURL handle to send multiple requests to the same target server, the same HTTP connection is being used internally, instead of being closed and reopened on every request.

Due to PHP's lifecycle however, all connections are closed automatically at the end of your script. For a CLI script this will probably not be an issue, but for a server-side script that is called frequently, the overhead of closing and re-opening connections for every single call is considerable for both client and server, and increases response times.

The same problem is encountered when connecting to databases in PHP: opening and closing a connection to a database in every single request slows down response times considerably.

## The Solution

[The PHP PDO library uses persistent connections](http://php.net/manual/en/pdo.connections.php) to avoid opening fresh connections to the database for every request. These connections are kept open after requests end, and are transparently reused in later requests. Should a connection drop, it will be automatically renewed. The script doesn't need to be aware this process, it just creates PDO objects with the appropriate connection string and persistent connections are automatically used behind the scenes.

PCURL applies the same principle to cURL simple and multi handles. Since these handles contain DNS resolver and HTTP connection caches, using them as often as possible will speed up response times considerably, after the initial build-up.

## Installation

This extension has been tested with HHVM 3.2 and is confirmed to work, the upcoming HHVM 3.3 should be compatible as well.

[Follow these instructions](https://github.com/facebook/hhvm/wiki/Prebuilt%20Packages%20for%20HHVM) to install **HHVM 3.2+** on your distro of choice. You'll also need the corresponding **development package**, which contains the `hphpize` tool and C++ headers for extension compilation, and should also pull in **GCC 4.8+** and **cmake** automatically.

Some of the following steps apply only to Ubuntu, if you use another distribution you may need to use different locations and another package manager.

**Note**: the Ubuntu package `hhvm-dev` doesn't set the executable flag on the `hphpize` binary, so you'll need to fix it:

    $ sudo apt-get install hhvm-dev
    $ sudo chmod a+x /usr/bin/hphpize

Now the source for the PCURL extension can be compiled:

    $ cd ext_pcurl
    $ cmake . && make

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

The PCURL extension's pool size is at most as large as the `ThreadCount` setting of your HHVM installation. PCURL manages two pools of the same size, one for simple and one for multi handles. It doesn't make sense to have more pooled handles than the maximum number of simultaneous requests that can occur.

### Additional Functions

** pcurl_pool_stats **

    string pcurl_pool_stats()

Returns an overview of the number of used and free handles in both the single and the multi cURL handle pools.

Example:

    <?php
    print(pcurl_pool_stats() . "\n");
    ?>

Output:

    single: free: 7, taken: 2; multi: free: 4, taken: 3

** pcurl_pool_reset **

    bool pcurl_pool_reset()

Disposes of all the free handles currently held by both pools. Returns `true` if both pools are completely empty after usage. Handles that are in active use are not closed.

Example:

    <?php
    var_dump(pcurl_pool_reset());
    print(pcurl_pool_stats() . "\n");
    ?>

Output:

    bool(false)
    single: free: 0, taken: 1; multi: free: 0, taken: 0

## Practical Advice

This extension works by holding onto cURL handles when they would normally be discarded. Connections cached within the handle will be kept open by the client (your server or script), but may be closed by the target server (the host of the URL you called). This case is handled transparently by cURL, which will reconnect when required, at the expense of setting up the connection again. This is why **on low-traffic servers, using PCURL might not bring any improvement over the default cURL extension**.

**On high-traffic servers, which have a somehow random call pattern to many different target servers, PCURL might also prove inefficient**. The reason for this is that once a connection to a server is opened, it is cached solely within its corresponding handle. This handle may be reused by requests which have no need for the opened connection, and instead open new connections to different servers. It may take some time until a request calling the same server gets a handle with an open connection to it, during which the server may have closed the connection. This will effectively use connections only once, but not close them, and use a large number of sockets as a result. You can check for this situation with `netstat`:

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

The high numer of `CLOSE_WAIT` connections indicated that their target servers have closed connections, but PCURL is still holding on to them. As a workaround, you can issue periodic calls to `pcurl_pool_reset()` but this situation is an indicator of the pooling pattern employed by PCURL not working efficient enough for your use case.

## License

This code is based on the cURL extension included with HHVM and uses the [PHP license](./LICENSE.PHP) like the original. The included header files have been taken straight from the HHVM project and are under their original license.


## Authors

The PCURL extension has been brought to you by the authors of the original [HHVM cURL extension](https://github.com/facebook/hhvm) and the [MobFox](https://github.com/mobfox) team.

Contributors:

* [Adrian Gligor](https://github.com/adriangligor)
