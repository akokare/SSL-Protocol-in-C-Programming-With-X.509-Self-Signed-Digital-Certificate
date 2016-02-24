# Secure Implementation of Inter-Process Communication using SSL protocol

Server side:
1.Declaration of clientaddr and servaddr of datatype struct sockaddr_in 
2.creating socket with some filedescriptor sockfd
 sockfd=connect(AF_INET, SOCK_STREAM,0);
3.assigning s_family
4.typecase port number to network understable format 'htons'
5.Bind() socket to the servaddr- which is the port number on the host machine
6.listen to the socket for any incoming packet
7. accept the connection through accept() from clientaddr
8. FINALLY, write the data 

Client side:
1.Declaration of clientaddr and servaddr of datatype struct sockaddr_in 
2.creating socket with some filedescriptor sockfd
3.Bind() socket to the servaddr- which is the port number on the host machine
4.accepts() the connection from server
5.Connects() to the server
