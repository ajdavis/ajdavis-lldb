LLDB Scripts for libbson and libmongoc 
======================================

A handy LLDB script for debugging C programs that use MongoDB with
[libbson or libmongoc](http://mongoc.org/). Two features are implemented so far:
it prints BSON data as JSON in the LLDB console, and prints a `bson_iter_t`
struct as a chunk of JSON with the `^` character indicating the iterator's
position.

For example, say you have a C program like:
    
     1  #include <bson.h>
     2  
     3  int main (int argc, char *argv[])
     4  {
     5     bson_t b;
     6  
     7     bson_init (&b);
     8     BSON_APPEND_INT32 (&b, "x", 1);
     9     BSON_APPEND_INT32 (&b, "y", 2);
    10     
    11     return 0;
    12  }

Compile this program:

    > clang `pkg-config --libs --cflags libbson-1.0` -g foo.c
 
This example LLDB session shows how a `bson_t` struct is pretty-printed with
either the standard `print` command or the custom `bson` command:

    > lldb a.out
    "bson" command installed by lldb_mongoc
    (lldb) breakpoint set -l 11
    (lldb) run
    Process 81202 stopped
       9   	   BSON_APPEND_INT32 (&b, "y", 2);
       10
    -> 11  	   return 0;
       12  	}

This is the exciting part - your `bson_t` is printed as JSON!

    (lldb) print b
    (bson_t) $0 = {
      "x": 1,
      "y": 2
    }

The "bson" command provides more options:

    (lldb) bson -v --one-line b
    len=19
    flags=INLINE|STATIC
    {"x": 1, "y": 2}
    (lldb) bson --raw b
    '\x13\x00\x00\x00\x10x\x00\x01\x00\x00\x00\x10y\x00\x02\x00\x00\x00\x00'

Type `help bson` for a list of options.

Install
-------

Requires [PyMongo](https://pypi.python.org/pypi/pymongo) and a build of
[libbson](http://mongoc.org/) with debug symbols.

## PyMongo

Install PyMongo with:

    python -m pip install pymongo

If you see "No module named pip" then you must
[install pip](https://pip.pypa.io/en/stable/installing/#installing-with-get-pip-py),
then run the previous command again.

## Configure LLDB

Place the [lldb_mongoc.py](https://raw.githubusercontent.com/ajdavis/lldb-mongoc/master/lldb_mongoc.py) file somewhere, and create a file `~/.lldbinit`
containing:

    command script import /path/to/lldb_mongoc.py

If you see `"bson" command installed by lldb_mongoc` at the beginning of your
LLDB session, you've installed the script correctly.

## Debug Build of libbson

If `print` or the `bson` command show "error: unable to read data" in the LLDB
console, you probably don't have libbson built with debug symbols.
Download latest mongo-c-driver.tar.gz from [mongoc.org](http://mongoc.org/) and
do:

    ./configure --enable-debug
    make
    sudo make install

License
-------

Apache 2.
