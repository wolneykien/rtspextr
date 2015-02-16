rtspextr(1) -- an RTSP-stream analyser/extractor
======================================================

SYNOPSIS
--------

`rtspextr` <br>
`rtspextr` `-u`|`--udp` <br>
`rtspextr` `-U`|`--unix` <br>
`rtspextr` `-P`|`--pcap` <br>

DESCRIPTION
-----------

`rtspextr` accepts an RTSP stream from `stdin` and analyses it
extracting the RTSP and payload (interleaved data) packets. The
extracted packets can be re-transmitted or dumped in various ways.

The following options are handled:

* `-h`, `--help`:
    print this help screen;
* `-q`, `--quiet`:
    output nothing;
* `-u` <IP>:<PORT>, `--udp=`<IP>:<PORT>:
    send data via UDP to IP:(PORT + CHN);
* `-U` <DIR>, `--unix=`<DIR>:
    send data to the local socket 'rtspextr.CHN' in the direcotry DIR;
* `-P` <DIR>, `--pcap=`<DIR>:
    write down libpcap dumps CHN.pcap' to the directory DIR (the
    option is available only when the program is built with libpcap
    support);
* `-C` <MAXCHN>, `--maxchn=`<MAXCHN>:
    limit the possible channel number to MAXCHN;
* `-L` <MAXLEN>, `--maxlen=`<MAXLEN>:
    limit the possible packet length to MAXLEN;
* `-R` <COUNT>, `--reportevery=`<COUNT>:
    print report every COUNT packets;
* `-e`, `--ignore-errors`:
    ignore the errors.


The *CHN* parameter above is the RTSP channel number (0--255).
It is used as suffix for socket and dump filenames. The special value
"rtsp" is used as suffix to send/dump the RTSP-data itself. When
retransmitting packages via UDP, the RTSP-data is always sent with
*PORT* + 256 as the destination port number.

In order to improve the RTSP stream identification by filtering out
the garbage trafic the valid channel value range is narrowed to 0--16
by default. This restriction can be overridden with the `-C` option.
The other disambiguation parameter is the RTSP channel payload maximal
length which is set to 2048 bytes by default and can be overridden
with the `-L` option.


EXAMPLES
--------

    # Retransmit the RTSP payload from the 'rtsp.test.stream' file
    # via UDP to the destination 192.168.0.55:1000:
    
    rtspextr -u 192.168.0.55:1000 <rtsp.test.stream
    
The channel number 0 data is sent to the port 1000, channel 1 --- 
to the port 1001 and so on. The RTSP data is sent to the port 1257.

    # Dump the RTSP stream from the 'rtsp.test.stream' file into
    # the set of *.pcap files in the directory 'rtsp.test.out':
    
    mkdir -p rtsp.test.out
    rtspextr -P rtsp.test.out <rtsp.test.stream
    
The channel number 0 data is written to the file
`rtsp.test.out/0.pcap`, channel 1 to the `rtsp.test.out/1.pcap` and so
on. The RTSP data is written to the `rtsp.test.out/rtsp.pcap` file.


AUTHORS
-------

  * Paul Wolneykien <p.wolneykien@metrotek.spb.ru>, 2014
