# gosoaap

A Go library for working with SOAAP results, as they are emitted by the SOAAP
tool in the textual JSON format.


## Installation

1. Install Go
  1. FreeBSD: `pkg install go`
  1. Mac OS X: `brew install go`
  1. [From source](https://golang.org/doc/install)

1. Set the `GOPATH` environment variable, e.g.:
    ```shell
    $ export GOPATH=$HOME/.go
    ```

1. Fetch and build this repository:
    ```shell
    $ go get github.com/CTSRD-SOAAP/gosoaap
    ```


## Commands

The library includes some command-line tools:

### soaap-parse

This tool parses the JSON output from SOAAP and converts it to a binary format
that other Go SOAAP tools can read. The `.gob` file extension (see
[gob package documentation](https://golang.org/pkg/encoding/gob/))
is recommended so that other tools can detect the use of the binary format
without having to examine the file itself:

```shell
$ soaap-parse --output=soaap.gob soaap-output.json
```


### soaap-graph

This tool opens a JSON or .gob file and converts it to a call graph in the
[GraphViz](http://www.graphviz.org) DOT format.
It currently only supports graphing the calls reachable from SOAAP
past-vulnerability warnings.
Usage:

```shell
$ soaap-graph --output=soaap.dot soaap.gob
$ dot -Tpdf -o soaap.pdf soaap.dot
```
