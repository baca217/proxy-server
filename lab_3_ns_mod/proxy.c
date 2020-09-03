#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>     /* for fgets */
#include <strings.h>    /* for bzero, bcopy */
#include <unistd.h>      /* for read, write */
#include <sys/socket.h>  /* for socket use */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <ctype.h>

#define MAXLINE 8192 /* max text line length */
#define LISTENQ 1024 /* second argument to listen() */
#define DEFPORT "80"
#define CHARHASH 25 /*max length to represent unsigned long*/
#define ERROR400 "HTTP/1.1 400 Bad Request\n"
#define ERROR403 "HTTP/1.1 403 Forbidden\n"
#define ERROR404 "HTTP/1.1 404 Not Found\n"
#define ERROR500 "HTTP/1.1 500 Internal Server Error\n"
#define ERROR503 "HTTP/1.1 503 Service Unavailable\n"
#define BLACKLIST "blacklist.txt"

int open_listenfd(int port);
int msg_work(int connfd, int ttl);
void term_char(char *host, char let);
int connect_http_server(char *host_name, char buf[MAXLINE], int clientfd);
char *pull_port(char *url);
bool in_cache(char *str, int clientfd, int ttl);
void cache_file(char *url, char *cont, int size);
void send_error(int connfd, int error);
bool is_blacklisted(char *url);
int check_args(int argc, char **argv, int *port, int *ttl);
void *thread(void *info);

struct args
{
	int connfd;
	int ttl;
};

int main(int argc, char **argv)
{
	int port, listenfd, ttl;
	socklen_t len = sizeof(struct sockaddr_in);
        struct sockaddr_in clientaddr;
	struct args *t_args;
	pthread_t tid;

	if(check_args(argc, argv, &port, &ttl) == -1)
		return -1;
	//setting up the listening fd
	if((listenfd = open_listenfd(port)) < 0)
        {
                printf("failed to bind\n");
                return -1;
        }


	while(1)
	{
		printf("WAITING\n");
		t_args = malloc(sizeof(struct args));
		t_args->connfd = accept(listenfd, (struct sockaddr*)&clientaddr, &len);
		t_args->ttl = ttl;
		if(t_args->connfd > 0)
                	pthread_create(&tid, NULL, thread, t_args);
		bzero((char *)&clientaddr, len);
	}

	return 0;
}

//function for intializing thread arguments
void* thread(void * info)
{
        struct args *t_args = (struct args *)info;
	int connfd = t_args->connfd;
	int ttl = t_args->ttl;
        pthread_detach(pthread_self());
        free(t_args);
        msg_work(connfd, ttl);
        close(connfd);
        return NULL;
}

int msg_work(int connfd, int ttl)
{
	char par_buf[MAXLINE];
	char par_cpy[MAXLINE];
	char meth[10];
	char ver[10];
	char *url = NULL;
	char *url_free = NULL;
	char *tok = NULL;	

	read(connfd, par_buf, MAXLINE);
	par_buf[MAXLINE] = '\0';
	strcpy(par_cpy, par_buf);

	//setting the method
	if((tok = strtok(par_buf, " ")) == NULL || strlen(tok) > 10)
	{
		printf("tok is empty or bigger than 10!!!(meth)\n");
		send_error(connfd, 400);
		return -1;
	}
	strcpy(meth, tok);
	if(strstr(meth, "GET") == NULL)
	{
		printf("Method is not GET!!!\n");
		send_error(connfd, 400);
		return -1;
	}
	//getting the url
	if((tok = strtok(NULL, " ")) == NULL)
	{
		printf("tok is empty!!!(url)\n");
		send_error(connfd, 400);
		return -1;
	}
	url = malloc(strlen(tok) + 1);
	url_free = url;
	bzero(url,strlen(tok));
	strcpy(url, tok);
	//getting the http version
	if((tok = strtok(NULL, "\n")) == NULL || strlen(tok) > 10)
	{
		printf("tok is empty or bigger than 10!!!(ver)\n");
		send_error(connfd, 400);
		free(url_free);
		return -1;
	}
	//checking if http version is supported
	if(strstr(tok, "HTTP/1.1") != NULL)
		strcpy(ver, "HTTP/1.1");
	else if(strstr(tok, "HTTP/1.0") != NULL)
		strcpy(ver, "HTTP/1.0");
	else
	{
		printf("version %s isn't supported\n", ver);
		send_error(connfd, 400);
		free(url_free);
		return -1;

	}
	//check if the url id blacklisted
	if(is_blacklisted(url))
	{
		send_error(connfd,403);
		free(url_free);
		return -1;
	}
	//check if the url is cached
	if(!in_cache(url, connfd, ttl))
	{
		connect_http_server(url, par_cpy, connfd);
	}
	free(url_free);
	return 1;
}

bool is_blacklisted(char *url)
{
	size_t size = 0;
	FILE *b_fp = NULL;
	char *line = NULL;
	size_t chars;
	
	if(!(b_fp = fopen(BLACKLIST, "r")))
	{
		printf("blacklist file doesn't exist\n");
		return false;
	}

	//iterating through blacklist file	
	while((chars = getline(&line, &size, b_fp)) != -1)
	{
		if(line[strlen(line)-1] == '\n')
			line[strlen(line)-1] = '\0';
		//checking if url is blacklisted
		if((strstr(url,line)) != NULL)
		{
			printf("Match: %s\nwebsite %s is blacklisted\n",line,url);
			fclose(b_fp);
			free(line);
			return true;
		}
	}

	fclose(b_fp);
	if(line)
		free(line);
	return false;
}


int connect_http_server(char *url, char buf[MAXLINE], int clientfd)
{
	int serv_len = sizeof(struct sockaddr_in), sockfd;
	int rec_size;
	struct hostent *server;
	struct sockaddr_in server_info;
	char rec_buf[MAXLINE];
	char *port = NULL;
	struct timeval tv;
	int optval = 1;
	char *tmp;
	char *url_cp = malloc(strlen(url) + 1);
	//initializing values
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	bzero(rec_buf, MAXLINE);
	bzero(url_cp, strlen(url) + 1);
	strcpy(url_cp, url);
	//change for easier parsing of url
	if((tmp = strstr(url, "//")) != NULL)
		url = tmp + 2;
	server_info.sin_family = AF_INET;
	//parsing for the port	
	port = pull_port(url);
	printf("PORT being used:%s\n",port);
	server_info.sin_port = htons(atoi(port));
	//terminating certain chars so gethostbyname() works
	term_char(url, ':');
	term_char(url, '/');
	//testing if url is an ip address
	if(inet_aton(url, &server_info.sin_addr) == 0)
	{
		//getting server ip through hostname
		server = gethostbyname(url);
		if(server)
		{
			server_info.sin_addr = *(struct in_addr *) server->h_addr;
		}
		else
		{
			printf("couldn't resolve servername: %s\n", url);
			free(url_cp);
			free(port);
			send_error(clientfd, 500);
			return -1;
		}
	}
	//setting up the connection to the http server
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
                printf("ERROR: couldn't bind socket");
                free(url_cp);
		free(port);
		send_error(clientfd, 500);
		return -1;
        }	
	/* Forces Bind SO_REUSEADDR is for FTP that requires reuse of same socket*/
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) < 0)
	{
		printf("failed to force re-binding to IP address\n");
		free(url_cp);
		free(port);
		send_error(clientfd, 500);
		return -1;
	}
	/*set timeout for receive socket*/
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0)
	{
		printf("failed to set receive timer\n");
		free(url_cp);
		free(port);
		send_error(clientfd, 500);
		return -1;
	}
	if(connect(sockfd, (struct sockaddr *)&server_info, serv_len) < 0)
        {
                printf("ERROR: Connect Failed\n");
                free(url_cp);
		free(port);
		close(sockfd);
		send_error(clientfd, 500);
		return -1;
        }
	printf("connection to http server established for: %s\n",url_cp);
	if(send(sockfd, buf, MAXLINE, 0) < 0)
	{
		printf("ERROR: message send failed\n");
		free(url_cp);
		free(port);
		close(sockfd);
		send_error(clientfd,500);
		return -1;
	}
	//CHANGE I MADE
	while((rec_size = read(sockfd, rec_buf, MAXLINE)) > 0)
	{
		write(clientfd, rec_buf, rec_size);
		cache_file(url_cp, rec_buf, rec_size);
		bzero(rec_buf, rec_size);
	}
	//CHANGE STOPS
	free(url_cp);
	free(port);
	close(sockfd);
	printf("exited!!!\n");
	return 0;
}

//meant to replace a given char with a null terminator
void term_char(char *host, char let)
{
	int i;
	for(i = 0; i < strlen(host); i++)
	{
		if(host[i] == let)
		{
			host[i] = '\0';
			break;
		}
	}
}

char *pull_port(char *url)
{
	int i, start = 0, end;
	char *port = NULL;
	for(i = 0; i < strlen(url); i++)
	{
		if(url[i] == ':')
		{
			start = i + 1;
		}
		if(start != 0 && url[i] == '/')
		{
			end = i - 1;
			port = malloc(end - start + 1);
			bzero(port, end - start + 1);
			break;
		}
	}
	//set port from parsing
	if(port)
	{
		char *spot = strstr(url,":");
		printf("spot: %s\n",spot);
		strncpy(port, spot+1, end - start + 1);
	}
	//default case set port to 80
	else
	{
		port = malloc(sizeof(char *) * (strlen(DEFPORT) + 1));
		bzero(port, strlen(DEFPORT) + 1);
		strcpy(port, DEFPORT);
	}
	return port;
}

bool in_cache(char *url, int clientfd, int ttl)
{
	unsigned long hash = 5381;
	int c;
	char c_hash[CHARHASH], *buf;
	FILE *fp;
	struct stat stats;
	time_t now;
	//hashing url
	while ((c = *url++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	//converting hash to string
	bzero(c_hash, CHARHASH);
	sprintf(c_hash, "%lu", hash);
	//checking if the file exists
	if((fp = fopen(c_hash,"r")))
	{
		//getting information if the file if it exists
		(stat(c_hash, &stats));
		//checking to see if file isn't too old
		time(&now);
		if(now - stats.st_mtime >= ttl)
		{
			printf("file in cache was too old\n");
			fclose(fp);
			remove(c_hash);
			return false;
		}
		int size = stats.st_size;
		//reading contents of the file
		buf = malloc(size + 1);
		bzero(buf, size + 1);
		fread(buf, size, 1, fp);
		//sending contents
		write(clientfd, buf, size+1);
		//freeing and closing
		fclose(fp);
		free(buf);
		printf("file was in cache\n");
		return true;

	}
	else
	{
		printf("file wasn't cached\n");
		return false;
	}
}

void cache_file(char *url, char cont[MAXLINE], int size)
{
	unsigned long hash = 5381;
	int c;
	char c_hash[CHARHASH];
	FILE *fp;
	//hashing
	while ((c = *url++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	//converting hash to string
	bzero(c_hash, CHARHASH);
	sprintf(c_hash, "%lu", hash);
	//writing content to a file
	if((fp = fopen(c_hash,"a")))
	{
		fwrite(cont, size, 1, fp);
		fclose(fp);
	}
	else
	{
		printf("failed to open cache file for writing\n");
	}
}

void send_error(int connfd, int error)
{
	switch(error)
	{
		case 400:
			write(connfd, ERROR400, strlen(ERROR400));
			break;
		case 403:
			write(connfd, ERROR403, strlen(ERROR403));
			break;
		case 404:
			write(connfd, ERROR404, strlen(ERROR404));
			break;
		case 500:
			write(connfd, ERROR500, strlen(ERROR500));
			break;	
		case 503:
			write(connfd, ERROR503, strlen(ERROR503));
			break;	
		default:
			printf("Error %d is unaccounted for\n",error);
	}
}

int check_args(int argc, char **argv, int *port, int *ttl)
{
	if(argc < 3)
	{
		printf("usage: ./proxy <port> <cache ttl>\n");
		return(-1);
	}
	if((*port = atoi(argv[1])) == 0)
	{
		printf("Please enter a number for port argument\n");
		return(-1);
	}
	if(*port < 5000 || *port > 65535)
	{
		printf("Please enter a port number greater than 5000 and less than 65535\n");
		return(-1);
	}
	if((*ttl = atoi(argv[2])) == 0)
	{
		printf("Please enter a number for the cache ttl\n");
		return(-1);
	}
	if(*ttl < 1)
	{
		printf("Please enter a cache ttl greater than 1\n");
		return(-1);
	}
	printf("Using port %d and cache ttl %d\n", *port, *ttl);
	return 0;
}

/*
 * open_listenfd - open and return a listening socket on port
 * Returns -1 in case of failure
 */
int open_listenfd(int port)
{
    int listenfd, optval=1;
    struct sockaddr_in serveraddr;

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("failed to create socket descriptor\n");
        return -1;
    }

    /* Forces Bind SO_REUSEADDR is for FTP that requires reuse of same socket*/
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval , sizeof(int)) < 0)
    {
        printf("failed to force re-binding to IP address\n");
        return -1;
    }

    /* listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);
    if (bind(listenfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
    {
            printf("failed to bind\n");
            return -1;
    }

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
    {
            printf("failed to listen\n");
        return -1;
    }
    return listenfd;
} /* end open_listenfd */

