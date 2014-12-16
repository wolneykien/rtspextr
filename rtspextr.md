rtspextr(1) -- an RTSP-stream analyser/extractor
======================================================

SYNOPSIS
--------

`rtspextr` <br>
`rtspextr` `-u`|`--udp` <br>
`rtspextr` `-U`|`--unix` <br>
`rtspextr` `-P`|`--pcap` <br>

## DESCRIPTION ##
-----------

`rtspextr` accepts an RTSP stream from `stdin` and analyses it
extracting the RTSP and payload (interleaved data) packets. The
extracted packets can be re-transmitted or dumped in various ways.

##OPTIONS

The following options are handled:

* `-h`, `--help`:
    print this help screen;
* `-q`, `--quiet`:
    output nothing;
* `-u` <IP>:<PORT>, `--udp=`<IP>:<PORT>:
    send data via UDP to IP:PORT;
* `-U` <DIR>, `--unix=`<DIR>:
    send data to the local socket 'rtspextr.PORT' in the direcotry DIR;
* `-P` <DIR>, `--pcap=`<DIR>:
    write down libpcap dumps 'PORT.pcap' to the directory DIR (the
    option is available only when the program is built with libpcap
    support);
* `-C` <MAXCHN>, `--maxchn=`<MAXCHN>:
    limit the possible channel number to MAXCHN;
* `-L` <MAXLEN>, `--maxlen=`<MAXLEN>:
    limit the possible packet length to MAXLEN;
* `-R` <COUNT>, `--reportevery=`<COUNT>:
    print report every COUNT packets.

AUTORS
------

  * Paul Wolneykien <p.wolneykien@metrotek.spb.ru>, 2014
