#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 1024
#define PORT 11111

char name[100] = "";

void ShowCerts(SSL * ssl)
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    //printf("Digital certificate information:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    //printf("Certificate: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
   // printf("Issuer: %s\n", line);
    free(line);
    X509_free(cert);
  }
  else
    printf("No certificate information！\n");
}

void getpeer (char *address, int portno, char *dest, char *money){
    int sockfd, n;
    struct sockaddr_in peer_addr;
    struct hostent *peer;
    struct in_addr ipv4addr;
    char buffer[1024];

    SSL_CTX *ctx;
    SSL *ssl;

    /* SSL 庫初始化 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        perror("ERROR opening socket");
    }
    inet_pton(AF_INET, address, &ipv4addr);
    peer = gethostbyaddr(&ipv4addr, sizeof(ipv4addr), AF_INET);

    if (peer == NULL){
        exit(0);
    }
    bzero((char *) &peer_addr, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    //bcopy((char *)peer->h_addr, (char *)&peer_addr.sin_addr.s_addr, peer->h_length);
    peer_addr.sin_port = htons(portno);

    if (connect(sockfd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0){
        perror("ERROR connecting");
        exit(1);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 連線 */
    if (SSL_connect(ssl) == -1){
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }

    printf("succeed!\n");
    char infor[1024] = "";
    strcpy(infor, name);
    strcat(infor, "#");
    strcat(infor, money);
    strcat(infor, "#");
    strcat(infor, dest);
    SSL_write(ssl, infor, strlen(infor));
}

void actserver(int portno){
    int sockfd, newsockfd;
    socklen_t clilen;
    char buffer[1024];
    struct sockaddr_in serv_addr, cli_addr;
    int n;
    SSL_CTX *ctx;
    mode_t mode;
    char pwd[100];
    char* temp;

    /* SSL 庫初始化 */
    SSL_library_init();
    /* 載入所有 SSL 演算法 */
    OpenSSL_add_all_algorithms();
    /* 載入所有 SSL 錯誤訊息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
    getcwd(pwd,100);
    if(strlen(pwd)==1)
        pwd[0]='\0';
    if (SSL_CTX_use_certificate_file(ctx, temp=strcat(pwd,"/cert.pem"), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 載入使用者私鑰 */
    getcwd(pwd,100);
    if(strlen(pwd)==1)
        pwd[0]='\0';
    if (SSL_CTX_use_PrivateKey_file(ctx, temp=strcat(pwd,"/key.pem"), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 檢查使用者私鑰是否正確 */
    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        perror("ERROR opening socket");
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        perror("ERROR on binding");
    listen(sockfd, 5);
    printf("running as p2p, listening.....\n");
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0) 
        perror("ERROR on accept");
    printf("connect to peer\n");
    SSL *ssl;
    /* 基於 ctx 產生一個新的 SSL */
    ssl = SSL_new(ctx);
    /* 將連線使用者的 socket 加入到 SSL */
    SSL_set_fd(ssl, newsockfd);
    /* 建立 SSL 連線 */
    if (SSL_accept(ssl) == -1)
    {
        perror("accept");
        close(newsockfd);
    }
    SSL_read(ssl, buffer, sizeof(buffer));
    printf("%s\n", buffer);
    char *deal[3] = {0};
    char msg[1024] = "Received ";
    int num = 0;
    char *rebuff = strtok(buffer, "#");
    while (rebuff != NULL){
        deal[num++] = rebuff;
        rebuff = strtok(NULL, "#");
    }
    strcat(msg, deal[1]);
    strcat(msg, " dollars from ");
    strcat(msg, deal[2]);
    strcat(msg, "\n");
    printf("%s\n", msg);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);
}

int Send (SSL *ssl){
    char input[500] = {0};
    int n = 0;
    int ab = 7536;    
    char *registered[2] = {0};
    char *deal[3] = {0};
    int num = 0;

    scanf("%s", input);    
    n = SSL_write(ssl, input, sizeof(input));

    if (strstr(input, "REGISTER#") != NULL){
        char *rebuff = strtok(input, "#");
        while (rebuff != NULL){
            registered[num++] = rebuff;
            rebuff = strtok(NULL, "#");
        }
        strcpy(name, registered[1]);
    }

    if (strstr(input, "Deal#") != NULL){
        //actserver(ab, ssl);
        char *rebuff = strtok(input, "#");
        while (rebuff != NULL){
            deal[num++] = rebuff;
            rebuff = strtok(NULL, "#");
        }
        getpeer("127.0.0.1", ab, deal[1], deal[2]);
    }

    if (strstr(input, "ready") != NULL){
        actserver(ab);
        //getpeer("127.0.0.1", ab, ssl);
    }

    if (strcmp(input, "Exit") == 0){
        return 1;
    }
    else return 0;
}

void Print (SSL *ssl){
    int val = 0;
    char buff[1024] = {0};
    val = SSL_read(ssl, buff, sizeof(buff));
    printf("%s", buff);
    
    if(strcmp(buff, "10000\n") == 0){
        bzero(buff, sizeof(buff));
        SSL_read(ssl, buff, sizeof(buff));
        printf("%s", buff);
    }
    return ;
}

int main(int argc, char const *argv[])
{
    int i,j,sock, len, fd, size;
    struct sockaddr_in dest;
    char buffer[1024] = {0};
    SSL_CTX *ctx;
    SSL *ssl;

    /* SSL 庫初始化 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 建立一個 socket 用於 tcp 通訊 */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化伺服器端（對方）的地址和埠資訊 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(PORT);
    if (inet_aton("127.0.0.1", (struct in_addr *) &dest.sin_addr.s_addr) == 0)
    {
        exit(errno);
    }
    printf("address created\n");

    /* 連線伺服器 */
    if (connect(sock, (struct sockaddr *) &dest, sizeof(dest)) != 0)
    {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n\n");

    /* 基於 ctx 產生一個新的 SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    /* 建立 SSL 連線 */
    if (SSL_connect(ssl) == -1){
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    bzero(buffer, MAXBUF);
    int valread, desc = 0;
    valread = SSL_read(ssl , buffer, sizeof(buffer));
    if (valread > 0){
        printf ("%s", buffer);
    }
    valread = 0;
    bzero(buffer, sizeof(buffer));

    while((desc = Send(ssl)) == 0){
        Print(ssl);
    }

    valread = SSL_read(ssl , buffer, sizeof(buffer));
    if (valread > 0){
        printf ("%s", buffer);
    }
    valread = 0;
    bzero(buffer, sizeof(buffer));

    /* 關閉連線 */
    close(fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}