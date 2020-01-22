# imap-notifier
Intended to be used with scripts included in my dotfiles.

## Usage
```bash
$ imap-notifier 0.1.0
Runs a script when an email arrives or a change in a subscribed folder occurs.

USAGE:
    imap-notifier [OPTIONS] <host> <user> <pass> <folder> <script>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --cafile <cafile>    Path to CA certificates. Defaults to system store
    -p, --port <port>        Port for IMAP server [default: 993]

ARGS:
    <host>      Host of IMAP server
    <user>      Username to use for authentication
    <pass>      Password to use for authentication
    <folder>    IMAP folder to watch for updates
    <script>    Script to be ran on notify. EXISTS is passed on new email, FLAGS with the flags are passed on
                read/update/delete

```
