
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>

#define BUFSIZE 65536

#define DEFIP "127.0.0.1"
#define DEFPORT 5440
#define DEFSOCKPATH "/tmp/rtpsock.%s" /* */
#define DEFDUMPPATH "rtp.%s.pcap" /* */
#define DEFRTSPCHN 256

#define DEFREPORTCOUNT 1024

#define SENDWHOLE

#undef UDP // #define UDP
#undef UNIX // #define UNIX
#define PCAP

#ifdef PCAP
#include <pcap/pcap.h>
#include <pcap/bpf.h>

#define PKTBUFSIZE 4096 /* */

#endif

struct input {
  FILE *stream;
  int sock;
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
  size_t total;
  size_t reported;
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
  int sock;
  struct sockaddr *srcaddr;
  struct sockaddr *destaddr;
  socklen_t addrlen;
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


void main( int argc, char **argv )
{
  uint8_t buf[ BUFSIZE ];
  struct bufdesc bufdesc = { buf, sizeof( buf ), buf, 0 };
  struct stats stats;
  int ret = 0;

  struct input in = { stdin, -1 };
  struct output out = { -1, NULL, NULL, 0 };

#ifdef UDP
  struct sockaddr_in destaddr_in;
  out.sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
  if ( out.sock < 0 ) {
    fprintf( stderr, "Unable to open output socket\n" );
    ret = 1;
  }
  destaddr_in.sin_family = AF_INET;
  destaddr_in.sin_port = htons( DEFPORT );
  if ( inet_aton( DEFIP, &destaddr_in.sin_addr ) == 0 ) {
    fprintf( stderr, "Incorrect IP address: %s\n", DEFIP );
    ret = 1;
  }
  out.destaddr = (struct sockaddr *) &destaddr_in;
  out.addrlen = sizeof( destaddr_in );
#endif

#ifdef UNIX
  struct sockaddr_un srcaddr_un;
  struct sockaddr_un destaddr_un;
  out.sock = socket( AF_UNIX, SOCK_DGRAM, 0 );
  destaddr_un.sun_family = AF_UNIX;
  out.destaddr = (struct sockaddr *) &destaddr_un;
  out.addrlen = sizeof( destaddr_un );
  if ( out.sock < 0 ) {
    fprintf( stderr, "Unable to open the socket\n" );
    ret = 1;
  }
  srcaddr_un.sun_family = AF_UNIX;
  snprintf( srcaddr_un.sun_path, sizeof( srcaddr_un.sun_path ),
           "%s%s", DEFSOCKPATH, "out" );
  unlink( srcaddr_un.sun_path );
  out.srcaddr = (struct sockaddr *) &srcaddr_un;
  ret = bind( out.sock, out.srcaddr, out.addrlen );
  if ( ret != 0 )
    perror( "Unable to bind the socket" );
#endif

#ifdef PCAP
  out.pcap = pcap_open_dead( DLT_EN10MB, PKTBUFSIZE );
  if ( out.pcap == NULL ) {
    fprintf( stderr, "Unable to get the libpcap handle\n" );
    ret = 1;
  }

  memcpy( out.pktbuf, &pkthdr, sizeof( pkthdr ) );
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

  if ( in->sock >= 0 ) {
    ret = close( in->sock );
    if ( ret != 0 ) {
      fprintf( stderr, "Error closing the input\n" );
      return ret;
    }
    in->sock = -1;
  }

  return 0;
}

int close_output( struct output *out ) {
  int p;
  int ret = 0;

  if ( out->sock >= 0 ) {
    for( p = DEFPORT; p <= (DEFPORT + DEFRTSPCHN); p++ ) {
      sendeof( out, p );
    }
    ret = close( out->sock );
    if ( ret != 0 ) {
      fprintf( stderr, "Error closing the output socket\n" );
    } else {
      out->sock = -1;
    }

    if ( ret == 0 ) {
      if ( out->destaddr->sa_family == AF_UNIX ) {
        unlink( ((struct sockaddr_un *)out->srcaddr)->sun_path );
      }
    }
  }

#ifdef PCAP
  if ( out->pcap ) {
    for( p = 0; p <= DEFRTSPCHN; p++ ) {
      if ( out->dumpers[ p ] )
        pcap_dump_close( out->dumpers[ p ] );
      out->dumpers[ p ] = NULL;
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
    if ( stats->total - stats->reported >= DEFREPORTCOUNT ) {
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
      }
      break;
    case RTSP:
      stats->total++;
      stats->rtsp++;
      ret = send_rtsp( in, out, buf, stats );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to read/send RTSP packet\n" );
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
  fprintf( stdout, "ERR Send/dump errors: %lu\n",
           stats->write_err );
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
  } else if ( in->sock >= 0 ) {
    // TODO: implement packet reading (1 packet at a time)
    fprintf( stderr, "Socket input isn't implemented yet\n" );
    return 255;
  }

  buf->offs = buf->buf;
  buf->avail += rd;

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

enum ptype find_pkt( struct input *in, struct bufdesc *buf,
                     struct stats *stats )
{
  int ret = 0;

  while ( ret == 0 ) {
    while ( buf->avail >= 4 ) {
      if ( *buf->offs == 0x24 ) {
        return BIN;
      }
      if ( strncmp( (char *) buf->offs, "RTSP", 4 ) == 0 ) {
        return RTSP;
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

int read_bin_header( struct input *in, struct bufdesc *buf,
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

  if ( skip( buf, 4 ) != 0 )
    return 1;

  return 0;
}

int setoutport( struct output *out, int chn )
{
  struct sockaddr_in *destaddr_in;
  struct sockaddr_un *destaddr_un;
  char suff[ 5 ];
  char dumppath[ sizeof( DEFDUMPPATH ) + 5 ];

  if ( out->destaddr ) {
    switch ( out->destaddr->sa_family ) {
    case AF_INET:
      destaddr_in = (struct sockaddr_in *) out->destaddr;
      destaddr_in->sin_port = htons( DEFPORT + chn );
      break;
    case AF_UNIX:
      destaddr_un = (struct sockaddr_un *) out->destaddr;
      if ( chn != DEFRTSPCHN )
        snprintf( suff, 5, "%i", chn );
      else
        snprintf( suff, 5, "%s", "rtsp" );
      snprintf( destaddr_un->sun_path,
                sizeof( destaddr_un->sun_path ),
                DEFSOCKPATH, suff );
      break;
    default:
      fprintf( stderr, "Unsupported destination address family: %i\n",
               out->destaddr->sa_family );
      return 1;
    }
  }
  
#ifdef PCAP
  if ( out->pcap ) {
    if ( out->dumpers[ chn ] == NULL ) {
      if ( chn != DEFRTSPCHN )
        snprintf( suff, 5, "%i", chn );
      else
        snprintf( suff, 5, "%s", "rtsp" );
      snprintf( dumppath, sizeof( dumppath ), DEFDUMPPATH, suff );
      out->dumpers[ chn ] = pcap_dump_open( out->pcap, dumppath );
      if ( out->dumpers[ chn ] == NULL ) {
        fprintf( stderr, "Unable to create the dumpfile %s\n",
                 dumppath );
        return 1;
      }
    }
    struct pkthdr *bufhdr = (struct pkthdr *) out->pktbuf;
    bufhdr->udp.dstport = htons( DEFPORT + chn );
  }
#endif

  return 0;
}

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

  if ( out->sock >=0 ) {
    ret = sendout( out, chn, buf, towrite, complete );
    if ( complete && ret == towrite ) {
      stats->sent++;
    }
    if ( ((int) ret) < 0 )
      return ret;
  }

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
    fprintf( stderr, "Error tokenize the RTSP status: %s\n",
             "name/version" );
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
    fprintf( stderr, "Error tokenize the RTSP status: %s\n",
             "code" );
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

  ret = read_ahead( in, buf );
  if ( ret != 0 ) {
    fprintf( stderr, "Unable to read the full RTSP header\n" );
    return ret;
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
