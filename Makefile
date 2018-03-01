all:	
	gcc -g -o epoll_httpd epoll_httpd.c hashtable.c
epoll_httpd:epoll_httpd.o hashtable.o
	gcc -o epoll_httpd epoll_http.o hashtable.o
epoll_httpd.o:epoll_httpd.c epoll_httpd.h hashtable.h
	gcc -g -c epoll_httpd.c
hashtable.o:hashtable.c hashtable.h
	gcc -g -c hashtable.c
clean:
	rm -rf epoll_httpd
	rm -rf *.o
