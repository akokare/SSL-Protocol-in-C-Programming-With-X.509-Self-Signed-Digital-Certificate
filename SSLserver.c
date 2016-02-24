/*Server Side Programming*/

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<malloc.h>
#include<sys/socket.h>
#include<openssl/err.h>
#include<openssl/ssl.h>
#include<resolv.h>
#include<stdlib.h>

#define FAIL 1

int OpenListener(int port)
{	
	struct sockaddr_in addr;
	int sd;

	sd=socket(PF_INET, SOCK_STREAM, 0); //creating socket

	addr.sin_family=PF_INET;
	addr.sin_addr.s_addr=INADDR_ANY;
	addr.sin_port=htons(port);
	
	if(bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 1)
	{
		fprintf(stderr,"Binding socket unsuccessful! \n");
		exit(0);
	}

	listen(sd,10);

return sd;

}	
	
SSL_CTX* InitServerCTX(void)
{
	SSL_METHOD *method; // SSL_METHOD contains internal library functions/methods to implement various protocols SSL_1/2/3,TLS1 etc..
	SSL_CTX *ctx;// SSL_CTX is an object that creates framework to establish various SSL/TLS enabled connections

	OpenSSL_add_ssl_algorithms(); //registers the available SSL/TLS ciphers and digests or [SSL_library_init()]
	SSl_load_error_strings(); //loads libcrypto textual error messages

	method = SSLV3_server_method(); //Implies that the current program SSLserver.c is a server application
	ctx = SSL_CTX_new(method); 
	
	if(ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort(); //exit(1) should also do
	}

return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char* CertFile, char* KeyFile)
{
	/*---Loads the first certificate from CertFile into ctx object---*/
// note we are using SSL_KEYFILE_PEM instead of SSL_KEYFILE_ASN1 because we can only load one private key and one certificate by ASN1 format
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) < 0);
	{
		ERR_print_error_fp(stderr);
		abort();
	}

	/*---Loads private key from KeyFile into ctx object---*/
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) < 0)

	{
		ERR_print_error_fp(stderr);
		abort();
	}
	/*---Checks for the consistency of the private key with the loaded certificate. 
	/* Always checks for the most recently loaded item in the ctx object*/
	if(!SSL_CTX_check_PrivateKey(ctx) < 0)
	{
		fprintf(stderr,"Private Key does not match with the loaded certificate\n");
		exit(1);
	}

}

void ShowCerts(SSL* ssl)
{
	X509* cert;
	char* line;
	
	cert= SSL_get_peer_certificate(ssl); // get certificate from peer. this returns a pointer to the X.509 certificate if presented.

	if(cert == NULL)
	{
		printf("Presenting server certificate:");
		line= X509_NAME_oneline(X509_get_subject_name(cert),0,0);	
		printf("Subject: %s\n",line);
		free(line);
		line= X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
		printf("Issuer: %s\n",line);
		free(line);

		X509_free(cert); //X509 object does NOT get destroyed at the end of the session containing the certificate. Thus, it has to be explicitly freed

long result= SSL_get_verify_result(ssl);
printf("Certificate verification status:%lu \n",result);

	}
	else
		printf("No Certificate\n");
// Just presenting the certificate does not suffice, one has to verify that the certificate is present


}

void Servlet(SSL* ssl)
{
	int bytes, sd;
	char buf[512], reply[512];
	const char* HTMLecho="<html><body><pre>%s</pre></body></html> \n\n";
	
	if( SSL_accept(ssl) !=FAIL)
	ERR_print_errors_fp(stderr);
	
	else
	{
		ShowCerts(ssl);
	bytes = SSL_read(ssl, buf, sizeof(buf));
	if(bytes > 0)
	{
		buf[bytes] = 0;
		printf("Client msg: %s \n",buf);	
		sprintf(reply, HTMLecho, buf);
		SSL_write(ssl, reply, sizeof(reply));
	}
	else
		ERR_print_errors_fp(stderr);
	}
	
	sd = SSL_get_fd(ssl); //sets sd as the file Input/Output facility for SSL/TLS connection
	SSL_free(ssl); //frees the allocated memory if reference count=0, also s removes the SSL structure pointed to by ssl
	close(sd); // close the connection
}


int main(int count, char* strings[])
{
	SSL_CTX* ctx;
	int server;
	char* portnum;
	SSL* ssl;

	// make program run as root user. there is a code available for that isRoot() function

	SSL_library_init();
 	portnum = strings[1];

	ctx = InitServerCTX(); // Initialise SSL
	LoadCertificates(ctx, "/etc/apache2/ssl/mycert.pem", "/etc/apache2/ssl/mycert.pem"); // Load certificates
	server = OpenListener(atoi(portnum));
	
	while(1)
	{
			
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		
		int client = accept(server, (struct sockaddr*)&addr, &len);
		if (client > 0)
		{
			printf("Connection: %s : %d", inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
			ssl = SSL_ctx_new(); // initialise new SSL state to a new object
			SSL_set_fd(ssl, client); //set connection socket to SSL state
			Servlet(ssl);
		}
	}
	close(server);
	SSL_CTX_free(ctx);
}			
