
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define BUFSIZE 65536

#define DEFPATH "/tmp/rtpsock."

#define DEFREPORTCOUNT 1024

struct stats {
  size_t total;
  size_t minlen;
  size_t maxlen;
  size_t reported;
};

int dump_packets( int sock, char *chn, struct stats *stats );

void main( int argc, char **argv )
{
  struct stats stats;
  int ret = 0;

  struct sockaddr_un sockaddr_un;
  int sock = socket( AF_UNIX, SOCK_DGRAM, 0 );
  if ( sock < 0 ) {
    fprintf( stderr, "Unable to open the socket\n" );
    ret = 1;
  }
  sockaddr_un.sun_family = AF_UNIX;
  snprintf( sockaddr_un.sun_path, sizeof( sockaddr_un.sun_path ),
           "%s%s", DEFPATH, argv[1] );
  unlink( sockaddr_un.sun_path );
  ret = bind( sock, (struct sockaddr *) &sockaddr_un,
              sizeof( sockaddr_un ) );
  if ( ret != 0 )
    perror( "Unable to bind the socket" );

  memset( &stats, 0, sizeof( stats ) );

  if ( ret == 0 )
    ret = dump_packets( sock, argv[1], &stats );

  close( sock );
  ret = unlink( sockaddr_un.sun_path );
  if ( ret != 0 )
    perror( "Unable to unlink the socket file" );

  exit( ret );
}

void report_stats( struct stats *stats )
{
  int i;

  fprintf( stdout, "RCVD Total packets received: %lu\n",
           stats->total );
  fprintf( stdout, "MIN Minimal packet length: %lu\n",
           stats->minlen );
  fprintf( stdout, "MAX Maximal packet length: %lu\n",
           stats->maxlen );

  fprintf( stdout, "\n" );
  
  stats->reported = stats->total;
}

int dump_packets( int sock, char *chn, struct stats *stats )
{
  uint8_t buf[ BUFSIZE ];  
  int ret = 0;

  size_t rcvd = 0;
  do {
    rcvd = recvfrom( sock, buf, sizeof( buf ), 0, NULL, NULL );
    if ( ((int) rcvd) < 0 ) {
      perror( "Receive error" );
      ret = errno;
    }
    
    stats->total++;    

    if ( rcvd > 0 && rcvd < stats->minlen || stats->minlen == 0 )
      stats->minlen = rcvd;
    if ( rcvd > stats->maxlen )
      stats->maxlen = rcvd;

    if ( stats->total - stats->reported >= DEFREPORTCOUNT )
      report_stats( stats );
  } while ( ((int) rcvd) > 0 );

  if ( stats->total > stats->reported )
      report_stats( stats );

  return ret;
}
