
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
#include <arpa/inet.h>

#define BUFSIZE 65536

#define DEFIP "127.0.0.1"
#define DEFPORT 5440
#define DEFCHN 0

#define DEFREPORTCOUNT 1024

struct input {
  FILE *stream;
  int sock;
};

struct stats {
  size_t rtsp;
  size_t rtsp_ok;
  size_t bin;
  size_t sent;
  size_t unmapped;
  size_t send_err;
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

struct chnmap {
  int chn;
  int sock;
  struct sockaddr *destaddr;
  socklen_t addrlen;
  struct chnmap *next;
};

int rtspextr( struct input *in, struct chnmap *chnmap,
              struct bufdesc *buf, struct stats *stats );
int close_input( struct input *in );
void report_stats( struct stats *stats );

void main( int argc, char **argv)
{
  uint8_t buf[ BUFSIZE ];
  struct bufdesc bufdesc = { buf, sizeof( buf ), buf, 0 };
  struct stats stats;

  struct input in = { stdin, -1 };

  int outsock = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );

  struct sockaddr_in destaddr1_in;
  destaddr1_in.sin_family = AF_INET;
  destaddr1_in.sin_port = htons( DEFPORT + 1);
  if ( inet_aton( DEFIP, &destaddr1_in.sin_addr ) == 0 ) {
    fprintf( stderr, "Incorrect addr: %s\n", DEFIP );
    exit( 1 );
  }
  struct sockaddr_in destaddr0_in;
  destaddr0_in.sin_family = AF_INET;
  destaddr0_in.sin_port = htons( DEFPORT );
  if ( inet_aton( DEFIP, &destaddr0_in.sin_addr ) == 0 ) {
    fprintf( stderr, "Incorrect addr: %s\n", DEFIP );
    exit( 1 );
  }
  struct chnmap chnmap1 = {
    DEFCHN + 1,
    outsock,
    (struct sockaddr *) &destaddr1_in,
    sizeof( destaddr1_in ),
    NULL
  };
  struct chnmap chnmap0 = {
    DEFCHN,
    outsock,
    (struct sockaddr *) &destaddr0_in,
    sizeof( destaddr0_in ),
    &chnmap1
  };

  memset( &stats, 0, sizeof( stats ) );

  int ret = rtspextr( &in, &chnmap0, &bufdesc, &stats );

  report_stats( &stats );

  close( outsock );
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


enum ptype find_pkt( struct input *in, struct bufdesc *buf,
                     struct stats *stats );
int send_bin( struct input *in, struct chnmap *chnmap,
              struct bufdesc *buf, struct stats *stats );
int skip_rtsp( struct input *in, struct bufdesc *buf,
               struct stats *stats );

int rtspextr( struct input *in, struct chnmap *chnmap,
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
      stats->bin++;
      ret = send_bin( in, chnmap, buf, stats );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to read/skip binary packet\n" );
      }
      break;
    case RTSP:
      stats->total++;
      stats->rtsp++;
      ret = skip_rtsp( in, buf, stats );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to read/skip RTSP packet\n" );
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
 fprintf( stdout, "TOTAL Total packets detected: %lu\n",
          stats->total );
 fprintf( stdout, "RTSP RTSP packets detected: %lu\n",
          stats->rtsp );
 fprintf( stdout, "RTSPOK Having '200 OK' status: %lu\n",
          stats->rtsp_ok );
 fprintf( stdout, "BIN Binary packets detected: %lu\n",
          stats->bin );
 fprintf( stdout, "SENT Packets sent: %lu\n",
          stats->sent );
 fprintf( stdout, "ERR Send errors: %lu\n",
          stats->send_err );
 fprintf( stdout, "UNMAP Unmapped channels: %lu\n",
          stats->unmapped );
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
  if ( toskip > buf->avail )
    toskip = buf->avail;

  buf->offs += toskip;
  buf->avail -= toskip;

  return toskip;
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
      skip( buf, 1 );
    }

    ret = read_next( in, buf );
  }

  if ( ret == 127 )
    return EOS;
  else
    return ERR;
}

int bin_header( struct bufdesc *buf, struct binpkt *hdr )
{
  if ( buf->avail < 4 ) {
    fprintf( stderr, "Need %lu more bytes to identify binary packet\n",
             4 - buf->avail );
    return 1;
  }

  hdr->mark = (char) *buf->offs;
  hdr->chn = *(buf->offs + 1);
  hdr->len = ntohs( *((uint16_t *) (buf->offs + 2)) );

  skip( buf, 4 );

  return 0;
}

size_t write_bin( struct chnmap *map, struct bufdesc *buf,
                  size_t towrite, int send, struct stats *stats )
{
  size_t wt = 0;

  wt = towrite;
  if ( send ) {
    stats->sent++;
  }

  return wt;
}

struct chnmap *getchnmap( struct binpkt *binpkt,
                          struct chnmap *chnmap )
{
  while ( chnmap != NULL ) {
    if ( chnmap->chn == binpkt->chn ) {
      return chnmap;
    }
    chnmap = chnmap->next;
  }
}

int send_bin( struct input *in, struct chnmap *chnmap,
              struct bufdesc *buf, struct stats *stats )
{
  int ret = 0;

  if ( buf->avail < 4 && buf->offs > buf->buf ) {
    ret = read_next( in, buf );
    if ( ret != 0 ) {
      fprintf( stderr, "Unable to read the interleaved packet " \
                       "header\n" );
      return ret;
    }
  }

  struct binpkt pkt;
  ret = bin_header( buf, &pkt );
  if ( ret != 0 ) return ret;

  struct chnmap *map = getchnmap( &pkt, chnmap );

  if ( map == NULL ) {
    // TODO: skip ?
    stats->unmapped++;
  }

  size_t wtotal = 0;

  while ( wtotal < pkt.len )
  {
    if ( buf->avail == 0 ) {
      ret = read_next( in, buf );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to read the next portion of the " \
                         "binary packet\n" );
        return ret;
      }
    }

    size_t towrite = pkt.len - wtotal < buf->avail ?
                       pkt.len - wtotal:
                       buf->avail;

    if ( map != NULL ) {
      size_t wt;
      wt = write_bin( map, buf, towrite,
                      wtotal + towrite == pkt.len, stats );
      if ( wt != towrite ) {
        stats->send_err++;
      }
    }

    wtotal += towrite;
    skip( buf, towrite );
  }

  return 0;
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
      skip( buf, (size_t) (endl - str) );

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

int skip_rtsp( struct input *in, struct bufdesc *buf,
               struct stats *stats )
{
  int ret = 0;

  if ( buf->offs > buf->buf ) {
    ret = read_next( in, buf );
    if ( ret != 0 ) {
      fprintf( stderr, "Unable to read the full RTSP header\n" );
      return ret;
    }
  }
  
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
      fprintf( stderr, "Next RTSP not found. " );
      fprintf( stderr, "Buffer seems to be too small\n" );
      return 1;
    }
  }

  size_t skipped = 0;
  while ( clen > skipped ) {
    if ( buf->avail == 0 ) {
      ret = read_next( in, buf );
      if ( ret != 0 ) {
        fprintf( stderr, "Unable to skip the next portion of the " \
                         "RTSP-packet\n" );
        return ret;
      }
    }
    size_t toskip = clen - skipped < buf->avail ?
                      clen - skipped:
                      buf->avail;
    skipped += skip( buf, toskip );
  }
  
  return 0;
}
