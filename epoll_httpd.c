/*
* Reference ngnix and tinyhttpd.
* Accept->Read request->Parse and handle->Send response.
* Read header, Parse header, Send header, Send response content.
* Read and write from tinyhttpd and tcpd are modified and added in above processes.
* !!!!Complie errors in get_index_file, send response and write. Fix them next week.
* Support CGI?
* Should be add file modify func. Like write modify time/date/year in header.
* Add run as daemon.
* Makefile how to.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <langinfo.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <unistd.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include "hashtable.h"
#include "epoll_httpd.h"

#define STATUS_READ_REQUEST_HEADER	0
#define STATUS_SEND_RESPONSE_HEADER	1
#define STATUS_SEND_RESPONSE		2

#define INET_ADDRLEN 20
#define INT_MAX 100*1024

#define NO_SOCK -1
#define NO_FILE -1

#define LOG_EN 1
#define NO_LOG 0

#define header_404 "HTTP/1.1 404 Not Found\r\nServer: epoll_http-server/1.0\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n<h1>Not found</h1>"
#define header_400 "HTTP/1.1 400 Bad Request\r\nServer: epoll_http-server/1.0\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n<h1>Bad request</h1>"
#define header_200_start "HTTP/1.1 200 OK\r\nServer: epoll_http-server/1.0\r\nContent-Type: text/html\r\nConnection: Close\r\n"

#define header_end "\r\n"

#define write_to_header(string_to_write) strcpy(process->buf + strlen(process->buf), string_to_write)
static struct sockaddr_in name;
static struct HashTable *processes;
static struct epoll_event event;
static int listen_sock;
static int efd,log_fd;
static char log_name[20];
static char* sock_char;

static char *doc_root;
static int current_total_processes;
static char *optstring;
static int opt;
static int log_status;
static char logbuf[4096*2];
static time_t t;
static struct tm* tp;
static char *str_time;
static short unsigned int port;
static char *ip_input;

static struct option long_options[] = {
    { "log", 1, NULL, 'l' },
    { "port",1 , NULL, 'p' },
    { "ip", 1, NULL, 'i'},
    { "file", 1, NULL, 'f'},
    { NULL, 0, NULL, 0}
};

int set_nonblocking ( int fd )
{
    int flags;

    /* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
    /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
    if ( -1 == ( flags = fcntl ( fd, F_GETFL, 0 ) ) )
        flags = 0;
    return fcntl ( fd, F_SETFL, flags | O_NONBLOCK );
#else
    /* Otherwise, use the old way of doing it */
    flags = 1;
    return ioctl ( fd, FIOBIO, &flags );
#endif
}

struct process* add_process ( struct HashTable* ht, int key, void* value, void(*free_value)(void*) )
{
    hash_table_put2( ht, key, value, free_value );
}

struct process* find_process ( HashTable* ht, int key )
{
    hash_table_get( ht, key );
}

void reset_process ( struct process* process )
{
    process->read_pos = 0;
    process->write_pos = 0;
}

static void free_process (void *process)
{
    free ( process );
}

static int open_log (int *log_fd)
{
    t = time ( NULL );
    tp = localtime( &t );
    sprintf ( str_time, "%2.2d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d\n", 
        tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec);
    
    if ( *log_fd = open( log_name, O_CREAT | O_WRONLY | O_APPEND, 0644) >= 0 )
	{
	/*
        ( void )write( log_fd, str_time, strlen( str_time ) );
	( void )write( log_fd, "\n", 1 );
	( void )close( log_fd );
	*/
	return 0;
	} else {
		return -1;
    }
}

void err_log_fmt( const char *file, int line, int status, const char *fmt, va_list args )
{
    char str[10240];
    int strLen = 0;
    char tmpStr[64];
    int tmpStrLen = 0;
    int pf = 0;

    /*Init*/
    memset ( str, 0, 10240 );
    memset ( tmpStr, 0, 64 );
    /*Add status*/
    if ( status )
    {
        tmpStrLen = sprintf ( str + strLen, "[ERROR STATUS is %d]",  status );
    } else {
        tmpStrLen = sprintf ( str + strLen, "[SUCCESS]");
    }

    /*add log info*/
    tmpStrLen = vsprintf( str + strLen, fmt, args );
    strLen += tmpStrLen;

    /*add file*/
    tmpStrLen = sprintf (str + strLen, " [%s]", file);

    /*add lines*/
    tmpStrLen = sprintf ( str + strLen, " [%d\n]", line );
    strLen += tmpStrLen;

    if ( open_log(&pf) != 0 )
    {
        return;
    }    

    write (pf, str, strLen);
    close (pf);
    return;
}

void err_log_write ( const char *file, int line, int status, const char *fmt, ... )
{
    va_list args;
    if(!status)
        return;
    
    va_start( args , fmt );
    err_log_fmt( file, line, status, fmt, args);
    va_end( args );

    return;
}

struct process* accept_sock ( int listen_sock )
{
    int s;
    //Must loop until -1 returned in ET mode
    while ( 1 )
    {
        struct sockaddr in_addr;
        socklen_t in_len;
        int infd;
        char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

		if ( current_total_processes >= MAX_PORCESS )
        {
            // Already reach max connections.
            infd = accept ( listen_sock, &in_addr, &in_len );
            if ( infd == -1 )
            {
                if ( ( errno == EAGAIN ) || ( errno == EWOULDBLOCK ) )
                {
                    // We have processed all incoming onnections.
                    break;
                }
                else
                {
                    err_log_write(__FILE__, __LINE__, log_status, "accept", 1);
                    break;
                }
            }
            close ( infd );
            return NULL;
        }
		
        in_len = sizeof in_addr;
        infd = accept ( listen_sock, &in_addr, &in_len );
        if ( infd == -1 )
        {
            if ( ( errno == EAGAIN ) || ( errno == EWOULDBLOCK ) )
            {
                //We have processed all incoming connections.
                break;
            }
            else
            {
                err_log_write(__FILE__, __LINE__, log_status, "accept", 1);
                break;
            }
        }

        getnameinfo ( &in_addr, in_len,
                      hbuf, sizeof hbuf,
                      sbuf, sizeof sbuf,
                      NI_NUMERICHOST | NI_NUMERICSERV );
        /* Make the incoming socket non-blocking and add it to the
           list of fds to monitor. */
        s = set_nonblocking ( infd );
        if ( s == -1 )
            abort ();
        int on = 1;
        setsockopt ( infd, SOL_TCP, TCP_CORK, &on, sizeof ( on ) );

        //Listen sock status
        event.data.fd = infd;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl ( efd, EPOLL_CTL_ADD, infd, &event );

        if ( s == -1 )
        {
            err_log_write(__FILE__, __LINE__, log_status, "epoll_ctl", 1);
            abort ();
        }

        struct process* process = ( struct process* )malloc(sizeof( struct process ));
        reset_process ( process );
        process->sock = infd;
        process->fd = NO_FILE;
        process->status = STATUS_READ_REQUEST_HEADER;
        add_process( processes, process->sock, process, free_process );
        current_total_processes++;
    }
}

//Add index.htm
int get_index_file ( char *filename_buf, struct stat *pstat )
{
    struct stat stat_buf;
    int s;
    s = lstat ( filename_buf, &stat_buf );
    if ( s == -1 )
    {
        // File or catalog doesn't exist 
        return -1;
    }
    if ( S_ISDIR ( stat_buf.st_mode ) )
    {
        // Is catalog or path? Add index.htm(l)
        strcpy ( filename_buf + strlen ( filename_buf ), INDEX_FILE );
        // Is file?
        s = lstat ( filename_buf, &stat_buf );
        if ( s == -1 || S_ISDIR ( stat_buf.st_mode ) )
        {
            // File doesn't exist or it is catalog or path
            int len = strlen ( filename_buf );
            filename_buf[len] = 'l';
            filename_buf[len + 1] = 0;
            s = lstat ( filename_buf, &stat_buf );
            if ( s == -1 || S_ISDIR ( stat_buf.st_mode ) )
            {
                // File doesn't exist or it is catalog or path
                return -1;
            }
        }
    }
    *pstat = stat_buf;
    return 0;
}

void read_request ( struct process* process )
{
    int sock = process->sock, s;
    char* buf = process->buf;
    char read_complete = 0;

    ssize_t count;

    while ( 1 )
    {
        count = read ( sock, buf + process->read_pos, BUF_SIZE - process->read_pos );
        if ( count == -1 )
        {
            if ( errno != EAGAIN )
            {
                handle_error ( process, "read request" );
                return;
            }
            else
            {
                //errno == EAGAIN --> finish read process
                break;
            }
        }
        else if ( count == 0 )
        {
            // Connection closed by client
            cleanup ( process );
            return;
        }
        else if ( count > 0 )
        {
            process->read_pos += count;
        }
    }

    int header_length = process->read_pos;

	// determine whether the request is complete
    if ( header_length > BUF_SIZE - 1 )
    {
		process->response_code = 400;
		process->status = STATUS_SEND_RESPONSE_HEADER;
		strcpy ( process->buf, header_400 );
		send_response_header ( process );
		handle_error ( process, "bad request" );
		return;
    }

	buf[header_length] = 0;
    read_complete = ( strstr ( buf, "\n\n" ) != 0 ) || ( strstr ( buf, "\r\n\r\n" ) != 0 );

    int error = 0;
    if ( read_complete )
    {
        //Reset read pos
        reset_process ( process );
        // get GET info
        if ( !strncmp ( buf, "GET", 3 ) == 0 )
        {
            process->response_code = 400;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_400 );
            send_response_header ( process );
            handle_error ( process, "bad request" );
            return;
        }
        // get first line
        unsigned int n_loc = ( unsigned long ) strchr ( buf, '\n' );
        unsigned int space_loc = ( unsigned long ) strchr ( buf + 4, ' ' );
        if ( n_loc <= space_loc )
        {
            process->response_code = 400;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_400 );
            send_response_header ( process );
            handle_error ( process, "bad request" );
            return;
        }
        char path[255];
        unsigned int len = space_loc - ( unsigned long ) buf - 4;
        if ( len > MAX_URL_LENGTH )
        {
            process->response_code = 400;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_400 );
            send_response_header ( process );
            handle_error ( process, "bad request" );
            return;
        }
        buf[header_length] = 0;
        strncpy ( path, buf+4, len );
        path[len] = 0;

        struct stat filestat;
        char fullname[256];
        char *prefix = doc_root;
        strcpy ( fullname, prefix );
        strcpy ( fullname + strlen ( prefix ), path );
        s = get_index_file ( fullname, &filestat);

		if ( s == -1 )
        {
            process->response_code = 404;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_404 );
            send_response_header ( process );
            handle_error ( process, "not found" );
            return;
        }

        int fd = open ( fullname, O_RDONLY );

        process->fd = fd;

		if ( fd < 0 )
        {
            process->response_code = 404;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_404 );
            send_response_header ( process );
            handle_error ( process, "not found" );
            return;
        }
        else
        {
            process->response_code = 200;
        }

        process->status = STATUS_SEND_RESPONSE_HEADER;
        //Modify socket status
        event.data.fd = process->sock;
        event.events = EPOLLOUT | EPOLLET;
        s = epoll_ctl ( efd, EPOLL_CTL_MOD, process->sock, &event );
        if ( s == -1 )
        {
            err_log_write(__FILE__, __LINE__, log_status, "epoll_ctl", 1);
            abort ();
        }
        //send header
        send_response_header ( process );
    }
}


int write_all ( struct process *process, char* buf, int n )
{
    int done_write = 0;
    int total_bytes_write = 0;
    while ( !done_write && total_bytes_write != n )
    {
        int bytes_write = write ( process->sock, buf + total_bytes_write, n - total_bytes_write );
        if ( bytes_write == -1 )
        {
            if ( errno != EAGAIN )
            {
                handle_error ( process, "write" );
                return 0;
            }
            else
            {
                // buf full
                return total_bytes_write;
            }
        }
        else
        {
            total_bytes_write += bytes_write;
        }
    }
    return total_bytes_write;
}


void send_response_header ( struct process *process )
{
    int s;
    if ( process->response_code != 200 )
    {
        int bytes_writen = write_all ( process, process->buf+process->write_pos, strlen ( process->buf )-process->write_pos );
        if ( bytes_writen == strlen ( process->buf ) + process->write_pos )
        {
            // write finish
            cleanup ( process );
        }
        else
        {
            process->write_pos += bytes_writen;
        }
    }
    else
    {
        int bytes_writen = write_all ( process, process->buf+process->write_pos, strlen ( process->buf )-process->write_pos );
        if ( bytes_writen == strlen ( process->buf ) + process->write_pos )
        {
            // write finish
            process->status = STATUS_SEND_RESPONSE;
            event.data.fd = process->sock;
            event.events = EPOLLOUT | EPOLLET;
            s = epoll_ctl ( efd, EPOLL_CTL_MOD, process->sock, &event );
            if ( s == -1 )
            {
                perror ( "epoll_ctl" );
                abort ();
            }
            send_response ( process );
        }
        else
        {
            process->write_pos += bytes_writen;
        }
    }
}

void send_response ( struct process *process )
{
    //Finish read file
    char end_of_file = 0;
    while ( 1 )
    {
        //Check if exist file already read but not write
        int size_remaining = process->read_pos - process->write_pos;
        if ( size_remaining > 0 )
        {
            // wirte
            int bytes_writen = write_all ( process, process->buf+process->write_pos, size_remaining );
            process->write_pos += bytes_writen;
            // Write finish? yes-->keep read, no -->return
            if ( bytes_writen != size_remaining )
            {
                // buf full
                return;
            }
        }
        if ( end_of_file )
        {
            //close file and socket
            cleanup ( process );
            return;
        }
        //read
        int done = 0;
        //synchronization
        process -> read_pos = 0;
        process -> write_pos = 0;
        while ( process->read_pos < BUF_SIZE )
        {
            int bytes_read = read ( process->fd, process->buf, BUF_SIZE - process->read_pos );
            if ( bytes_read == -1 )
            {
                if ( errno != EAGAIN )
                {
                    handle_error ( process, "read file" );
                    return;
                }
                break;
            }
            else if ( bytes_read == 0 )
            {
                end_of_file = 1;
                break;
            }
            else if ( bytes_read > 0 )
            {
                process->read_pos += bytes_read;
            }
        }
    }
}

void cleanup ( struct process *process )
{
    int s;
    if ( process->sock != NO_SOCK )
    {
        s = close ( process->sock );
        current_total_processes --;
        if ( s == NO_SOCK )
        {
            err_log_write(__FILE__, __LINE__, log_status, "close sock", 1);
        }
    }
    if ( process->fd != -1 )
    {
        s = close ( process->fd );
        if ( s == NO_FILE )
        {
            printf ( "fd: %d\n",process->fd );
            printf ( "\n" );
            err_log_write(__FILE__, __LINE__, log_status, "close file", 1);
        }
    }
    process->sock = NO_SOCK;
    reset_process ( process );
}

void handle_error ( struct process* process, char* error_string )
{
    cleanup ( process );
    perror ( error_string );
}

void handle_request ( int sock )
{
    if ( sock == listen_sock )
    {
        accept_sock ( sock );
    }
    else
    {
        struct process* process = find_process ( processes, sock );
        if ( process != 0 )
        {
            switch ( process->status )
            {
            case STATUS_READ_REQUEST_HEADER:
                read_request ( process );
                break;
            case STATUS_SEND_RESPONSE_HEADER:
                send_response_header ( process );
                break;
            case STATUS_SEND_RESPONSE:
                send_response ( process );
                break;
            default:
                break;
            }
        }
    }
}

//Modified online blog version
static int create_and_bind ( char *ip, int port )
{
    int httpd = 0;
    /*port reuse*/
    int opt = 1;
    httpd = socket( PF_INET, SOCK_STREAM, 0 );

    if ( httpd == -1 )
    {
        fprintf ( stderr, "socket\n" );
        return -1;
    }
    
    setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof ( opt ) );
    memset ( &name, 0, sizeof ( name ) );
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = inet_addr( ip );
    name.sin_port = htons( port );

    if ( bind(httpd, (struct sockaddr *)&name, sizeof( name )) < 0 )
    {
        fprintf ( stderr, "Could not bind\n" );
        return -1;
    }

    if ( !port )
    {
        int namelen = sizeof( name );
        if (getsockname(httpd, (struct sockaddr *)&name, (socklen_t *)&namelen ) == -1 )
        {
            fprintf ( stderr, "Counld not getsockname\n" );
            return -1;
        }
        port = ntohs( name.sin_port );
    }

    return httpd;
}

void init_processes()
{
    hash_table_delete( processes );
}

void sighandler ( int sig )
{
    exit ( 0 );
}

int main ( int argc, char *argv[] )
{
    int s;
    struct epoll_event *events;
    processes = hash_table_new();

    signal ( SIGABRT, &sighandler );
    signal ( SIGTERM, &sighandler );
    signal ( SIGINT, &sighandler );

    /*Useage: ./xxx --ip ip --port (port) --log logname --file doc_root*/
    optstring = "i:plf:";
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL )) != -1 )
    {
        switch ( opt )
        {
            case 'l' :
                log_status = LOG_EN;
		sprintf(log_name, "httpd_1/%s.txt", optarg);
		printf ("Server logfile :  %s\n", log_name);
		break;
            case 'p' :
                port = atoi(optarg);
		printf ("Server port : %d\n", port);
		break;
            case 'i' :
                ip_input = optarg;
		printf ("Server ip : %s\n", optarg);
		break;
            case 'f' :
                doc_root = optarg;
		printf ("Server doc_root : %s\n", doc_root);
		break;
        }
    }

    if ( argc != 9 )
    {
		fprintf ( stderr, "Useage:--ip ip --port (port) --log logname --file doc_root\n");
		fprintf ( stderr, "%s, %s, %s, %s, %s, %s, %s, %s, %s\n", argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]);
        exit ( EXIT_FAILURE );
    }

    init_processes();

    listen_sock = create_and_bind ( ip_input, port );
    if ( listen_sock == -1 )
        abort ();

    s = set_nonblocking ( listen_sock );
    if ( s == -1 )
        abort ();

    s = listen ( listen_sock, SOMAXCONN );
    if ( s == -1 )
    {
        err_log_write(__FILE__, __LINE__, log_status, "listen", 1);
        abort ();
    }

    efd = epoll_create1 ( 0 );
    if ( efd == -1 )
    {
        err_log_write(__FILE__, __LINE__, log_status, "epoll_create", 1);
        abort ();
    }

    event.data.fd = listen_sock;
    event.events = EPOLLIN | EPOLLET;
    s = epoll_ctl ( efd, EPOLL_CTL_ADD, listen_sock, &event );
    if ( s == -1 )
    {
        err_log_write(__FILE__, __LINE__, log_status, "epoll_ctl", 1);
        abort ();
    }

    // Buffer where events are returned 
    events = calloc ( MAXEVENTS, sizeof event );

    //The event loop
    while ( 1 )
    {
        int n, i;

        n = epoll_wait ( efd, events, MAXEVENTS, -1 );
        if ( n == -1 )
        {
            err_log_write(__FILE__, __LINE__, log_status, "epoll_wait", 1);
        }
        for ( i = 0; i < n; i++ )
        {
            if ( ( events[i].events & EPOLLERR ) ||
                    ( events[i].events & EPOLLHUP ) )
            {
                /* An error has occured on this fd, or the socket is not
                   ready for reading.*/
                fprintf ( stderr, "epoll error\n" );
                close ( events[i].data.fd );
                continue;
            }

            handle_request ( events[i].data.fd );

        }
    }

    free ( events );

    close ( listen_sock );

    return EXIT_SUCCESS;
}

