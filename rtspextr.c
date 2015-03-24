
// Copyright (C) 2014  Paul Wolneykien <wolneykien@gmail.com>
// Copyright (C) 2014  STC Metrotek [http://metrotek.spb.ru/]
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(UDP) || defined(UNIX)
#include <sys/socket.h>
#endif

#ifdef UDP
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef UNIX
#include <sys/un.h>
#endif

#include <errno.h>
#include <getopt.h>


#define BUFSIZE 65536

#define DEFIP "127.0.0.1"
#define DEFPORT 5440
#define DEFSOCKDIR "/tmp"
#define DEFSOCKPATH "%s/rtspextr.%s" /* */
#define DEFDUMPDIR "./"
#define DEFDUMPPATH "%s/%s.pcap" /* */
#define DEFRTSPCHN 256

#define DEFMAXCHN 16
#define DEFMAXLEN 2048

#define DEFREPORTCOUNT 1024

#define SENDWHOLE

#ifdef PCAP
#include <pcap/pcap.h>
#include <pcap/bpf.h>

#define PKTBUFSIZE 65536 /* */

#endif


struct params {
#ifdef UDP
  char *destip;
#endif
  uint16_t destport;
#ifdef UNIX
  char *sockdir;
#endif
#ifdef PCAP
  char *dumpdir;
#endif
  int maxchn;
  size_t maxlen;
  size_t reportcount;
  int dosend;
  int ignore_errors;
} varparams = {
#ifdef UDP
  NULL,
#endif
  DEFPORT,
#ifdef UNIX
  NULL,
#endif
#ifdef PCAP
  NULL,
#endif
  DEFMAXCHN, DEFMAXLEN, DEFREPORTCOUNT, /* */
  0, 0,
}; /* */

struct params *params = &varparams; /* */


struct input {
  FILE *stream;
#ifdef UDP
  int sock;
#endif
  size_t pos;
};

struct stats {
  size_t rtsp;
  size_t rtsp_ok;
  size_t tbin;
  size_t tbin_b;
  size_t chnbin[ DEFRTSPCHN ];
  size_t chnbin_b[ DEFRTSPCHN ];
  size_t sent;
  size_t write_err;
  size_t dumped;
  size_t other;
  int otherflag;
  size_t total;
  size_t reported;
  size_t lastpos;
};

struct binpkt {
  char mark;
  uint8_t chn;
  uint16_t len;
};

enum ptype { BIN, RTSP, EOS, ERR };

struct bufdesc {
  uint8_t *buf;
  size_t len;
  uint8_t *offs;
  size_t avail;
};

#ifdef PCAP
struct ethhdr {
  uint8_t macdst[ 6 ];
  uint8_t macsrc[ 6 ];
  uint8_t etype[ 2 ];
};

struct iphdr {
  uint8_t ver_ihl;
  uint8_t dscp_ecn;
  uint16_t iplen;
  uint16_t ident;
  uint8_t flags_foffs[ 2 ];
  uint8_t ttl;
  uint8_t proto;
  uint16_t hdchksum;
  uint8_t ipsrc[ 4 ];
  uint8_t ipdst[ 4 ];
};

struct udphdr {
  uint8_t srcport[ 2 ];
  uint16_t dstport;
  uint16_t udplen;
  uint16_t udpchksum;
};

struct pkthdr {
  struct ethhdr eth;
  struct iphdr ip;
  struct udphdr udp;
} pkthdr = {
  /* Ethernet */
  {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },       // macdst
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },       // macsrc
    { 0x08, 0x00 },                               // etype
  },

  /* IPv4 */
  {
    0x45, // ver.2, header length 20 bytes        // ver_ihl
    0x00,                                         // dscp_ecn
    0x0000,                                       // iplen
    0x0000,                                       // ident
    { 0x40, 0x00 }, // don't fragment             // flags_foffs
    0x40, // 64                                   // ttl
    0x11, // UDP                                  // proto
    0x0000,                                       // hdchksum
    { 0x7f, 0x00, 0x00, 0x01 },                   // ipsrc
    { 0x7f, 0x00, 0x00, 0x01 },                   // ipdst
  },

  /* UDP */
  {
    { 0x02, 0x2a },  // 554 (RTP)                 // srcport
    0x0000,                                       // dstport
    0x0000,                                       // udplen
    0x0000,                                       // udpchksum
  },
};
#endif

struct output {
#if defined(UDP) || defined(UNIX)
  int sock;
  struct sockaddr *srcaddr;
  struct sockaddr *destaddr;
  socklen_t addrlen;
#ifdef UDP
  struct sockaddr_in destaddr_in;
#endif
#ifdef UNIX
  struct sockaddr_un srcaddr_un;
  struct sockaddr_un destaddr_un;
#endif

#endif

#ifdef PCAP
  pcap_t *pcap;
  pcap_dumper_t *dumpers[ DEFRTSPCHN + 1 ];
  uint8_t pktbuf[ PKTBUFSIZE ];
#endif
};


int rtspextr( struct input *in, struct output *out,
              struct bufdesc *buf, struct stats *stats );
int close_input( struct input *in );
int close_output( struct output *out );
void report_stats( struct stats *stats );

#ifdef UDP
int init_socket_udp( struct output *out );
#endif
#ifdef UNIX
int init_socket_unix( struct output *out );
#endif
#ifdef PCAP
int init_pcap( struct output *out );
#endif

void parse_opts( int argc, char **argv );

void main( int argc, char **argv )
{
  uint8_t buf[ BUFSIZE ];
  struct bufdesc bufdesc = { buf, sizeof( buf ), buf, 0 };
  struct stats stats;
  int ret = 0;

  parse_opts( argc, argv );

  struct input in;
  in.stream = stdin;
#ifdef UDP
  in.sock = -1;
#endif
  in.pos = 0;

  struct output out;
#if defined(UDP) || defined(UNIX)
  out.sock = -1;
  out.srcaddr = NULL;
  out.destaddr = NULL;
  out.addrlen = 0;
#endif
#ifdef PCAP
  out.pcap = NULL;
  memset( out.dumpers, 0, sizeof( out.dumpers ) );
#endif

#ifdef UDP
  if ( ret == 0 && out.sock < 0 && params->destip ) {
    ret = init_socket_udp( &out );
    params->dosend = 1;
  }
#endif

#ifdef UNIX
  if ( ret == 0 && out.sock < 0 && params->sockdir ) {
    ret = init_socket_unix( &out );
    params->dosend = 1;
  }
#endif

#ifdef PCAP
  if ( ret == 0 && out.pcap == NULL && params->dumpdir ) {
    ret = init_pcap( &out );
    params->dosend = 1;
  }
#endif

  memset( &stats, 0, sizeof( stats ) );

  if ( ret == 0 ) {
    ret = rtspextr( &in, &out, &bufdesc, &stats );
    report_stats( &stats );
  }

  close_output( &out );
  close_input( &in );

  exit( ret );
}


extern char *basename (const char *__filename);

void print_help( int argc, char **argv )
{
  fprintf( stdout, "Usage %s [ options ]\n", basename( argv[0] ) );
  fprintf( stdout, "\n" );
  fprintf( stdout, "Options:\n" );
  fprintf( stdout, "\n" );
  fprintf( stdout, "  %-29s   %s;\n",
           "-h, --help", "print this help screen" );
  fprintf( stdout, "  %-29s   %s;\n",
           "-q, --quiet", "output nothing" );
#ifdef UDP
  fprintf( stdout, "  %-29s   %s;\n",
           "-u IP:PORT, --udp=IP:PORT",
           "send data via UDP to IP:PORT" );
#endif
#ifdef UNIX
  fprintf( stdout, "  %-29s   %s\n%34s%s;\n",
           "-U DIR, --unix=DIR",
           "send data to the local socket", " ",
           "'rtspextr.PORT' in the direcotry DIR" );
#endif
#ifdef PCAP
  fprintf( stdout, "  %-29s   %s\n%34s%s;\n",
           "-P DIR, --pcap=DIR", "write libpcap dumps", " ",
           "'PORT.pcap' in the directory DIR" );
#endif
  fprintf( stdout, "  %-29s   %s\n%34s%s;\n",
           "-C MAXCHN, --maxchn=MAXCHN",
           "limit the possible channel number", " ",
           "to MAXCHN" );
  fprintf( stdout, "  %-29s   %s\n%34s%s;\n",
           "-L MAXLEN, --maxlen=MAXLEN",
           "limit the possible packet length", " ",
           "to MAXLEN" );
  fprintf( stdout, "  %-29s   %s.\n",
           "-R COUNT, --reportevery=COUNT",
           "print report every COUNT packets" );
  fprintf( stdout, "  %-29s   %s.\n",
           "-e, --ignore-errors",
           "ignore the errors" );
}

void parse_opts( int argc, char **argv )
{
  int c;
  int optidx;
  char *endptr;

  static struct option opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "quiet", no_argument, NULL, 'q' },
#ifdef UDP
    { "udp", required_argument, NULL, 'u' },
#endif
#ifdef UNIX
    { "unix", required_argument, NULL, 'U' },
#endif
#ifdef PCAP
    { "pcap", required_argument, NULL, 'P' },
#endif
    { "maxchn", required_argument, NULL, 'C' },
    { "maxlen", required_argument, NULL, 'L' },
    { "reportevery", required_argument, NULL, 'R' },
    { "ignore-errors", no_argument, NULL, 'e' },
    { NULL, 0, NULL, 0 }
  };

  while ( (c = getopt_long( argc, argv, "hqu:U:P:C:L:R:e",
                            opts, &optidx )) >= 0 )
  {
    switch (c) {
    case 0:
      fprintf( stderr, "Unexpected long option: %s\n",
               opts[optidx].name );
      exit( -1 );
    case 'h':
      print_help( argc, argv );
      exit( 0 );
    case 'q':
      params->reportcount = 0;
      break;;
#ifdef UDP
    case 'u':
      params->destip = strtok( optarg, ":" );
      if ( params->destip == NULL ) {
        fprintf( stderr, "Invalid IP:PORT string: %s\n", optarg );
        exit( -1 );
      }
      params->destport =
        (uint16_t) strtoul( optarg, &endptr, 10 );
      if ( endptr && *endptr != '\0' ) {
        fprintf( stderr, "Invalid IP:PORT string: %s\n", optarg );
        exit( -1 );
      }
      break;;
#endif
#ifdef UNIX
    case 'U':
      params->sockdir = optarg;
      break;
#endif
#ifdef PCAP
    case 'P':
      params->dumpdir = optarg;
      break;;
#endif
    case 'C':
      params->maxchn = (int) strtol( optarg, &endptr, 10 );
      if ( endptr && *endptr != '\0' ) {
        fprintf( stderr, "Invalid number: %s\n", optarg );
        exit( -1 );
      }
      break;
    case 'L':
      params->maxlen = (int) strtol( optarg, &endptr, 10 );
      if ( endptr && *endptr != '\0' ) {
        fprintf( stderr, "Invalid number: %s\n", optarg );
        exit( -1 );
      }
      break;
    case 'R':
      params->reportcount = (size_t) strtoul( optarg, &endptr, 10 );
      if ( endptr && *endptr != '\0' ) {
        fprintf( stderr, "Invalid number: %s\n", optarg );
        exit( -1 );
      }
      break;
    case 'e':
      params->ignore_errors = 1;
      break;;
    default:
      fprintf( stderr, "Try `%s --help` for a biref help page\n",
               basename( argv[0] ) );
      exit( -1 );
    }
  }
}

#ifdef UDP
int init_socket_udp( struct output *out )
{
  if ( out->sock >= 0 ) {
    fprintf( stderr, "Socket already open\n" );
    return 1;
  }

  out->sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
  if ( out->sock < 0 ) {
    fprintf( stderr, "Unable to open output socket\n" );
    return 1;
  }

  out->destaddr_in.sin_family = AF_INET;
  out->destaddr_in.sin_port = htons( params->destport );
  if ( inet_aton( params->destip, &out->destaddr_in.sin_addr ) == 0 ) {
    fprintf( stderr, "Incorrect IP address: %s\n", params->destip );
    return 1;
  }

  out->destaddr = (struct sockaddr *) &out->destaddr_in;
  out->addrlen = sizeof( out->destaddr_in );

  return 0;
}
#endif

#ifdef UNIX
int init_socket_unix( struct output *out )
{
  if ( out->sock >= 0 ) {
    fprintf( stderr, "Socket already open\n" );
    return 1;
  }

  int ret = 0;

  out->sock = socket( AF_UNIX, SOCK_DGRAM, 0 );
  out->destaddr_un.sun_family = AF_UNIX;
  out->destaddr = (struct sockaddr *) &out->destaddr_un;
  out->addrlen = sizeof( out->destaddr_un );
  if ( out->sock < 0 ) {
    fprintf( stderr, "Unable to open the socket\n" );
    return 1;
  }

  out->srcaddr_un.sun_family = AF_UNIX;
  snprintf( out->srcaddr_un.sun_path,
            sizeof( out->srcaddr_un.sun_path ),
           "%s%s", params->sockdir, "out" );
  unlink( out->srcaddr_un.sun_path );
  out->srcaddr = (struct sockaddr *) &out->srcaddr_un;
  ret = bind( out->sock, out->srcaddr, out->addrlen );

  if ( ret != 0 )
    perror( "Unable to bind the socket" );

  return ret;
}
#endif

#ifdef PCAP
int init_pcap( struct output *out )
{
  if ( out->pcap != NULL ) {
    fprintf( stderr, "PCAP already initialized\n" );
    return 1;
  }

  out->pcap = pcap_open_dead( DLT_EN10MB, PKTBUFSIZE );
  if ( out->pcap == NULL ) {
    fprintf( stderr, "Unable to get the libpcap handle\n" );
    return 1;
  }

  memcpy( out->pktbuf, &pkthdr, sizeof( pkthdr ) );
  return 0;
}
#endif

int close_input( struct input *in ) {
  int ret = 0;

  if ( in->stream ) {
    ret = fclose( in->stream );
    if ( ret != 0 ) {
      fprintf( stderr, "Error closing the input stream\n" );
      return ret;
    }
    in->stream = NULL;
  }

#ifdef UDP
  if ( in->sock >= 0 ) {
    ret = close( in->sock );
    if ( ret != 0 ) {
      fprintf( stderr, "Error closing the input\n" );
      return ret;
    }
    in->sock = -1;
  }
#endif

  return 0;
}

int close_output( struct output *out ) {
  int i;
  int ret = 0;

#if defined(UDP) || defined(UNIX)
  if ( out->sock >= 0 ) {
    for( i = 0; i <= DEFRTSPCHN; i++ ) {
      sendeof( out, i );
    }
    ret = close( out->sock );
    if ( ret != 0 ) {
      fprintf( stderr, "Error closing the output socket\n" );
    } else {
      out->sock = -1;
    }

#ifdef UNIX
    if ( ret == 0 ) {
      if ( out->destaddr->sa_family == AF_UNIX ) {
        unlink( ((struct sockaddr_un *)out->srcaddr)->sun_path );
      }
    }
#endif
  }
#endif

#ifdef PCAP
  if ( out->pcap ) {
    for( i = 0; i <= DEFRTSPCHN; i++ ) {
      if ( out->dumpers[ i ] )
        pcap_dump_close( out->dumpers[ i ] );
      out->dumpers[ i ] = NULL;
    }
  
    pcap_close( out->pcap );
  }
#endif

  return ret;
}


enum ptype find_pkt( struct input *in, struct bufdesc *buf,
                     struct stats *stats );
int send_bin( struct input *in, struct output *out,
              struct bufdesc *buf, struct stats *stats );
int send_rtsp( struct input *in, struct output *out,
               struct bufdesc *buf, struct stats *stats );

int rtspextr( struct input *in, struct output *out,
              struct bufdesc *buf, struct stats *stats )
{
  int ret = 0;

  while ( ret == 0 ) {
    if ( stats->total - stats->reported >= params->reportcount ) {
      report_stats( stats );
    }

    enum ptype ptype = find_pkt( in, buf, stats );

    switch ( ptype ) {
    case BIN:
      stats->total++;
      stats->tbin++;
      ret = send_bin( in, out, buf, stats );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to read/send binary packet\n" );
        if ( params->ignore_errors ) {
          fprintf( stderr, "Error ignored\n" );
          ret = 0;
        }
      }
      break;
    case RTSP:
      stats->total++;
      stats->rtsp++;
      ret = send_rtsp( in, out, buf, stats );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to read/send RTSP packet\n" );
        if ( params->ignore_errors ) {
          fprintf( stderr, "Error ignored\n" );
          ret = 0;
        }
      }
      break;
    case EOS:
      ret = 127;
      break;
    case ERR:
      ret = 255;
    }
  }

  if ( ret == 127 )
    ret = 0;

  return ret;
}

void report_stats( struct stats *stats )
{
  int i;

  if ( params->reportcount == 0 ) {
    stats->reported = stats->total;
    return;
  }

  fprintf( stdout, "DEC Total packets detected: %lu\n",
           stats->total );
  fprintf( stdout, "RTSP RTSP packets detected: %lu\n",
           stats->rtsp );
  fprintf( stdout, "RTSPOK Having '200 OK' status: %lu\n",
           stats->rtsp_ok );

  for ( i = 0; i < DEFRTSPCHN; i++ ) {
    if ( stats->chnbin[ i ] ) {
      fprintf( stdout, "BIN.%i Channel #%i binary packets detected: %lu\n",
               i, i, stats->chnbin[ i ] );
      fprintf( stdout, "BINB.%i Channel #%i Binary traffic, bytes: %lu\n",
               i, i, stats->chnbin_b[ i ] );
    }
  }
 
  fprintf( stdout, "TBIN Total binary packets detected: %lu\n",
           stats->tbin );
  fprintf( stdout, "TBINB Total binary traffic, bytes: %lu\n",
           stats->tbin_b );
  fprintf( stdout, "SENT Packets sent: %lu\n",
           stats->sent );
  if ( params->dosend ) {
    fprintf( stdout, "ERR Send/dump errors: %lu\n",
             stats->write_err );
  }
  fprintf( stdout, "UNDET Uknown traffic, bytes: %lu\n",
          stats->other );
  fprintf( stdout, "\n" );
  
  stats->reported = stats->total;
}

int read_next( struct input *in, struct bufdesc *buf )
{
  if ( buf->avail > 0 && buf->offs > buf->buf ) {
    memmove( buf->buf, buf->offs, buf->avail );
  }

  buf->offs = buf->buf + buf->avail;

  size_t toread = buf->len - ((size_t) (buf->offs - buf->buf));

  size_t rd;
  if ( in->stream ) {
    if ( feof ( in->stream ) )
      return 127;
    rd = fread( buf->offs, 1, toread, in->stream );
    if ( rd < toread ) {
      if ( ferror( in->stream ) ) {
        fprintf( stderr, "I/O stream read error\n" );
        return 255;
      }
    }
#ifdef UDP
  } else if ( in->sock >= 0 ) {
    // TODO: implement packet reading (1 packet at a time)
    fprintf( stderr, "Socket input isn't implemented yet\n" );
    return 255;
#endif
  }

  buf->offs = buf->buf;
  buf->avail += rd;

  in->pos += rd;

  return 0;
}

int skip( struct bufdesc *buf, size_t toskip )
{
  if ( toskip > buf->avail ) {
    fprintf( stderr, "Unable to skip %lu bytes: only %lu is " \
                     "available\n",
             toskip, buf->avail );
    return 1;
  }

  buf->offs += toskip;
  buf->avail -= toskip;

  return 0;
}

int unskip( struct bufdesc *buf, size_t tounskip )
{
  if ( (buf->offs - tounskip) < buf->buf ) {
    fprintf( stderr, "Unable to unskip %lu bytes: only %lu is " \
                     "available\n",
             tounskip, (size_t) (buf->offs - buf->buf) );
    return 1;
  }

  buf->offs -= tounskip;
  buf->avail += tounskip;

  return 0;
}

int peek_bin_header( struct input *in, struct bufdesc *buf,
                     struct binpkt *hdr );

enum ptype find_pkt( struct input *in, struct bufdesc *buf,
                     struct stats *stats )
{
  int ret = 0;

  while ( ret == 0 ) {
    while ( buf->avail >= 4 ) {
      if ( *buf->offs == 0x24 ) {
        struct binpkt binhdr;
        if ( peek_bin_header( in, buf, &binhdr ) != 0 )
          return ERR;
        if ( binhdr.chn <= params->maxchn &&
             binhdr.len <= params->maxlen ) 
        {
          stats->otherflag = 0;
          stats->lastpos = in->pos - buf->avail;
          return BIN;
        }
      }
      if ( strncmp( (char *) buf->offs, "RTSP", 4 ) == 0 ) {
        stats->otherflag = 0;
        stats->lastpos = in->pos - buf->avail;
        return RTSP;
      }

      if ( !stats->otherflag ) {
        stats->otherflag = 1;
        fprintf( stderr, "Unknown data at %08lx + %02lx, " \
                         "last packet at %08lx + %02lx\n",
                 ((in->pos - buf->avail) / 16) * 16,
                 (in->pos - buf->avail) % 16,
                 (stats->lastpos / 16) * 16,
                 stats->lastpos % 16 );
      }
      stats->other++;
      if ( skip( buf, 1 ) != 0 )
        return ERR;
    }

    ret = read_next( in, buf );
  }

  if ( ret == 127 )
    return EOS;
  else
    return ERR;
}

int read_ahead( struct input *in, struct bufdesc *buf )
{
  if ( buf->offs > buf->buf ) {
    return read_next( in, buf );
  } else {
    return 0;
  }
}

int peek_bin_header( struct input *in, struct bufdesc *buf,
                     struct binpkt *hdr )
{
  int ret = 0;

  if ( buf->avail < 4 ) {
    ret = read_ahead( in, buf );
    if ( ret != 0 ) {
      fprintf( stderr, "Unable to read the interleaved packet " \
                       "header\n" );
      return ret;
    }
  }

  if ( buf->avail < 4 ) {
    fprintf( stderr, "Need %lu more bytes to identify binary packet\n",
             4 - buf->avail );
    return 1;
  }

  hdr->mark = (char) *buf->offs;
  hdr->chn = *(buf->offs + 1);
  hdr->len = ntohs( *((uint16_t *) (buf->offs + 2)) );

  return 0;
}

int read_bin_header( struct input *in, struct bufdesc *buf,
                     struct binpkt *hdr )
{
  int ret = 0;

  ret = peek_bin_header( in, buf, hdr );
  if ( ret != 0 )
    return ret;

  if ( skip( buf, 4 ) != 0 )
    return 1;

  return 0;
}

int setoutport( struct output *out, int chn )
{
  struct sockaddr_in *destaddr_in;
  struct sockaddr_un *destaddr_un;
  char suff[ 5 ];
  static char dumppath[ 1024 ];

#if defined(UDP) || defined(UNIX)
  if ( out->destaddr ) {
    switch ( out->destaddr->sa_family ) {
#ifdef UDP
    case AF_INET:
      destaddr_in = (struct sockaddr_in *) out->destaddr;
      destaddr_in->sin_port = htons( params->destport + chn );
      break;
#endif
#ifdef UNIX
    case AF_UNIX:
      destaddr_un = (struct sockaddr_un *) out->destaddr;
      if ( chn != DEFRTSPCHN )
        snprintf( suff, 5, "%i", chn );
      else
        snprintf( suff, 5, "%s", "rtsp" );
      snprintf( destaddr_un->sun_path,
                sizeof( destaddr_un->sun_path ),
                DEFSOCKPATH, params->sockdir, suff );
      break;
#endif
    default:
      fprintf( stderr, "Unsupported destination address family: %i\n",
               out->destaddr->sa_family );
      return 1;
    }
  }
#endif
  
#ifdef PCAP
  if ( out->pcap ) {
    if ( out->dumpers[ chn ] == NULL ) {
      if ( chn != DEFRTSPCHN )
        snprintf( suff, 5, "%i", chn );
      else
        snprintf( suff, 5, "%s", "rtsp" );
      snprintf( dumppath, sizeof( dumppath ), DEFDUMPPATH,
                params->dumpdir, suff );
      out->dumpers[ chn ] = pcap_dump_open( out->pcap, dumppath );
      if ( out->dumpers[ chn ] == NULL ) {
        fprintf( stderr, "Unable to create the dumpfile %s\n",
                 dumppath );
        return 1;
      }
    }
    struct pkthdr *bufhdr = (struct pkthdr *) out->pktbuf;
    bufhdr->udp.dstport = htons( params->destport + chn );
  }
#endif

  return 0;
}

#if defined(UDP) || defined(UNIX)
size_t sendout( struct output *out, int chn,
                const void *buf, size_t towrite, int send )
{
  int flags = 0;

  if ( !send )
    flags |= MSG_MORE;
  
  size_t wt = sendto( out->sock, buf, towrite, flags,
                      (struct sockaddr *) out->destaddr,
                      out->addrlen );

  if ( ((int) wt) < 0 ) {
    if ( errno == ENOENT )
      wt = 0;
  }

  return wt;
}
#endif

#ifdef PCAP
size_t dump( struct output *out, int chn,
             const void *buf, size_t towrite, int complete )
{
  size_t ret = 0;
  
  if ( !complete ) {
    fprintf( stderr, "Can't dump incomplete packet\n" );
    errno = ECANCELED;
    ret = -1;
  } else {
    if ( sizeof( pkthdr ) + towrite > PKTBUFSIZE ) {
      fprintf( stderr, "Packet dump buffer too small\n" );
      ret = -1;
    } else {
      struct pkthdr *bufhdr = (struct pkthdr *) out->pktbuf;
      bufhdr->ip.iplen = htons( sizeof( struct pkthdr )
                                - sizeof( struct ethhdr )
                                + towrite );
      bufhdr->udp.udplen = htons( sizeof( struct pkthdr )
                                  - sizeof( struct ethhdr )
                                  - sizeof( struct iphdr )
                                  + towrite );
      memcpy( out->pktbuf + sizeof( pkthdr ), buf, towrite );
      struct pcap_pkthdr phdr;
      phdr.caplen = sizeof( pkthdr ) + towrite;
      phdr.len = phdr.caplen;
      gettimeofday( &phdr.ts, NULL );
      pcap_dump( (u_char *) out->dumpers[ chn ], &phdr, out->pktbuf );
      ret = towrite;
    }
  }
  
  return ret;
}
#endif

size_t writeout( struct output *out, int chn,
                 const void *buf, size_t towrite, int complete,
                 struct stats *stats )
{
  size_t ret = 0;

  if ( setoutport( out, chn ) != 0 )
    return -1;

#if defined(UDP) || defined(UNIX)
  if ( out->sock >=0 ) {
    ret = sendout( out, chn, buf, towrite, complete );
    if ( complete && ret == towrite ) {
      stats->sent++;
    }
    if ( ((int) ret) < 0 )
      return ret;
  }
#endif

#ifdef PCAP
  if ( out->pcap ) {
    ret = dump( out, chn, buf, towrite, complete );
    if ( complete && ret == towrite ) {
      stats->dumped++;
    }
    if ( ((int) ret) < 0 )
      return ret;
  }
#endif

  return ret;
}

#if defined(UDP) || defined(UNIX)
int sendeof( struct output *out, int chn )
{
  int ret = 0;

  ret = setoutport( out, chn );
  if ( ret != 0 )
    return ret;

  size_t wt = sendto( out->sock, NULL, 0, 0,
                      (struct sockaddr *) out->destaddr,
                      out->addrlen );

  if ( ((int) wt) < 0 ) {
    ret = errno;
    if ( errno == ENOENT )
      ret = 0;
  }

  return ret;
}
#endif

int send_bin( struct input *in, struct output *out,
              struct bufdesc *buf, struct stats *stats )
{
  int ret = 0;

  struct binpkt pkt;
  ret = read_bin_header( in, buf, &pkt );
  if ( ret != 0 ) return ret;

  stats->chnbin[ pkt.chn ]++;

  size_t wtotal = 0;

  int write_err = 0;
  while ( wtotal < pkt.len )
  {
    if ( buf->avail == 0 ) {
      ret = read_next( in, buf );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to read the next portion of the " \
                         "binary packet\n" );
        return ret;
      }
    } else {
#ifdef SENDWHOLE
      if ( buf->avail < pkt.len ) {
        ret = read_ahead( in, buf );
        if ( ret != 0 ) {
          fprintf( stderr, "Unable to read the whole binary packet\n" );
          return ret;
        }
      }
#endif
    }

    size_t towrite = pkt.len - wtotal < buf->avail ?
                       pkt.len - wtotal :
                       buf->avail;

    size_t wt = writeout( out, pkt.chn, buf->offs, towrite,
                          wtotal + towrite == pkt.len, stats );
    if ( ((int) wt) < 0 ) {
      perror( "Unable to send/write the binary packet" );
      return 1;
    }
    if ( wt != towrite )
      write_err = 1;

    stats->chnbin_b[ pkt.chn ] += towrite;
    stats->tbin_b += towrite;

    wtotal += towrite;
    if ( skip( buf, towrite ) != 0 )
      return 1;
  }

  if ( write_err )
    stats->write_err++;

  return ret;
}


char *zero_endl( struct bufdesc *buf )
{
  char chr1, chr2;
  int ret = 0;

  if ( buf->avail > 0 ) {
    chr1 = '\r'; chr2 = '\n';
    char *endl = (char *) memchr( buf->offs, chr1, buf->avail );
    if ( !endl ) {
      chr1 = '\n'; chr2 = '\r';
      endl = (char *) memchr( buf->offs, chr1, buf->avail );
    }
    if ( endl ) {
      *endl = '\0';
      endl++;
      if ( ((size_t) (endl - (char *) buf->offs)) < buf->avail &&
           *endl == chr2 )
        {
          *endl = '\0';
          endl++;
        }

      char *str = (char *) buf->offs;
      if ( skip( buf, (size_t) (endl - str) ) != 0 )
        return NULL;

      return str;
    }
  }

  return NULL;
}

int parse_rtsp_status( char *str, struct stats *stats )
{
  int vhi, vlo, code;
  char *ctx;
  int ret;

  char *namever = strtok_r( str, " \t", &ctx );
  if ( namever == NULL ) {
    fprintf( stderr, "Error tokenize the RTSP name/version: %s\n",
             str );
    return 1;
  }
  ret = sscanf( namever, "RTSP/%d.%d", &vhi, &vlo );
  if ( ret != 2 ) {
    fprintf( stderr, "Error parse the RTSP status: %s\n",
             "name/version" );
    return 1;
  }

  char *codestr = strtok_r( NULL, " \t", &ctx );
  if ( codestr == NULL ) {
    if ( strlen( ctx ) == 0 ) {
      return 0;
    }
    fprintf( stderr, "Error tokenize the RTSP code: %s\n",
             str );
    return 1;
  }
  ret = sscanf( codestr, "%d", &code );
  if ( ret != 1 ) {
    fprintf( stderr, "Error parse the RTSP status: %s\n",
             "code" );
    return 1;
  }

  if ( code == 200 ) {
    stats->rtsp_ok++;
  }

  //char *ststr = strtok_r( NULL, "\r\n", &ctx );

  return 0;
}

int parse_rstp_header( char* str, char **name, char **val )
{
  char *ctx;

  *name = strtok_r( str, ": \t", &ctx );
  if ( *name == NULL ) {
    fprintf( stderr, "Error tokenize an RTSP header:\n" );
    return 1;
  }

  *val = strtok_r( NULL, "\r\n", &ctx );

  return 0;
}

int send_rtsp( struct input *in, struct output *out,
               struct bufdesc *buf, struct stats *stats )
{
  int ret = 0;

  if ( buf->avail < 32 ) {
    ret = read_ahead( in, buf );
    if ( ret != 0 ) {
      fprintf( stderr, "Unable to read the full RTSP header\n" );
      return ret;
    }
  }

  uint8_t *rtspoffs = buf->offs;
  
  char *status = zero_endl( buf );
  if ( status != NULL ) {
    ret = parse_rtsp_status( status, stats );
    if ( ret != 0 ) return ret;
  } else {
    fprintf( stderr, "The RTSP status header not found\n" );
    return 1;
  }

  size_t clen = 0;
  while ( buf->avail > 0 ) {
    char *nextln = zero_endl( buf );
    if ( nextln != NULL ) {
      if ( strlen( nextln ) == 0 ) break; // end of headers

      char *hdrname, *hdrval;
      ret = parse_rstp_header( nextln, &hdrname, &hdrval );
      if ( ret != 0 ) return ret;
      
      if ( strcmp( hdrname, "Content-Length" ) == 0 ) {
        char *tail;
        clen = (size_t) strtoul( hdrval, &tail, 10 );
        if ( strlen( tail ) != 0 ) {
          fprintf( stderr, "Error parsing the %s value\n",
                   hdrname );
          return 1;
        }
      }
    } else {
      fprintf( stderr, "Next RTSP header not found. " );
      fprintf( stderr, "Buffer seems to be too small\n" );
      return 1;
    }
  }

  size_t wtotal = 0;
  int write_err = 0;
  size_t rtsphdrlen = (size_t) (buf->offs - rtspoffs);
  size_t rtsplen = rtsphdrlen + clen;

  if ( unskip( buf, rtsphdrlen ) != 0 )
    return 1;

  size_t towrite;
  size_t wt;

#ifndef SENDWHOLE
  towrite = rtsphdrlen;
  wt = writeout( out, DEFRTSPCHN, buf->offs, towrite,
                 clen == 0, stats );
  if ( ((int) wt) < 0 ) {
    perror( "Unable to send/write the RTSP packet header" );
    return 1;
  }
  if ( wt != towrite )
    write_err = 1;
  wtotal += towrite;
  if ( skip( buf, towrite ) != 0 )
    return 1;
#endif

  while ( wtotal < rtsplen ) {
#ifdef SENDWHOLE
    if ( buf->avail < rtsplen ) {
      fprintf( stderr, "Unable to read the whole RTSP packet\n" );
      return 1;
    }
#else
    if ( buf->avail == 0 ) {
      ret = read_next( in, buf );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to read the next portion of the " \
                         "RTSP packet\n" );
        return ret;
      }
    }
#endif

    towrite = rtsplen - wtotal < buf->avail ?
                rtsplen - wtotal :
                buf->avail;
    wt = writeout( out, DEFRTSPCHN, buf->offs, towrite,
                   wtotal + towrite == rtsplen, stats );
    if ( ((int) wt) < 0 ) {
      perror( "Unable to send/write the RTSP packet" );
      return 1;
    }
    if ( wt != towrite )
      write_err = 1;

    wtotal += towrite;
    if ( skip( buf, towrite ) != 0 )
      return 1;
  }

  if ( write_err )
    stats->write_err++;
  
  return 0;
}
