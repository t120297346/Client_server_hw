#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include<pthread.h>
#include <ctype.h>

#define MAXBUF 1024
#define max_size 100
#define max_online 10
#define PORT 11111

int n = 0;
char *ip[10] ={0};
char *nn[10] = {0};
//pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

struct userdata{
    char username[max_size];
    char portNum[max_size];
    char ipaddr[max_size];
    int  amount;
};
struct linklist{
    struct userdata data;
    struct linklist *nextPtr;
};
typedef struct linklist Linklist;

Linklist *startPtr = NULL;

int checkname(char *name){
    if (n < 2){
        return 1;
    }
    for (int i = 0; i < n-1; i++){
        if (strcmp(name, nn[i]) == 0){
            return 0;
        }
        else return 1;
    }    
}

int checkport(char *port, Linklist *currentPtr){
    while (currentPtr != NULL){
        if (strcmp(port, currentPtr->data.portNum) == 0){
            return 0;
        }
        else return 1;
    }    
}

void add(char *name, char *pt, char *addr, int money, Linklist **starP){
    Linklist *newPtr, *currentPtr;
    newPtr = malloc(sizeof(Linklist));
    strcpy(newPtr->data.username, name);
    strcpy(newPtr->data.ipaddr, addr);
    strcpy(newPtr->data.portNum, pt);
    newPtr->data.amount = money;
    newPtr->nextPtr =NULL;

    if(*starP == NULL){
        *starP = newPtr;
    }
    else{
        currentPtr = *starP;
        while(currentPtr != NULL){
            if(currentPtr->nextPtr == NULL){
                currentPtr->nextPtr = newPtr;
                break;
            }
            currentPtr = currentPtr->nextPtr;
        }        
    }
}

void plus(char *dealer, int coco, Linklist *currentPtr){
    while (currentPtr != NULL){
        if (strcmp(dealer, currentPtr->data.username) == 0){
            currentPtr->data.amount = currentPtr->data.amount + coco;
            printf("%d\n", currentPtr->data.amount);
            break;
        }
        currentPtr = currentPtr->nextPtr;
    }
}

void reduce(char *owner, int coco, Linklist *currentPtr){
    while (currentPtr != NULL){
        if (strcmp(owner, currentPtr->data.username) == 0){
            currentPtr->data.amount = currentPtr->data.amount - coco;
            printf("%d\n", currentPtr->data.amount);
            break;
        }
        currentPtr = currentPtr->nextPtr;
    }
}

void sendlog(SSL *ssl, Linklist *currentPtr){
    if (currentPtr == NULL) {
        printf("no list data\n");
    }
    else{
        for (int i = 0; i < n-1; i++){
            currentPtr = currentPtr->nextPtr;
        }
        char mes_login[MAXBUF]; 
        sprintf(mes_login, "%d", currentPtr->data.amount);
        strcat(mes_login, "\n");
        char number[20];
        sprintf(number, "numbers of account online: %d", n);
        strcat(mes_login, number);
        strcat(mes_login, "\n");
        strcat(mes_login, currentPtr->data.username);
        strcat(mes_login, " form #");
        strcat(mes_login, currentPtr->data.ipaddr);
        strcat(mes_login, " with port:");
        strcat(mes_login, currentPtr->data.portNum);
        strcat(mes_login, "\n");
        //puts(mes_login);
        SSL_write(ssl , mes_login , strlen(mes_login));
    }
    return;
}

void sendlist(SSL *ssl, Linklist *currentPtr){
    if (currentPtr == NULL) {
        printf("no list data\n");
    }
    else{
        char mes_list[MAXBUF] = "";
        char money[MAXBUF] = "";
        char number[20];
        sprintf(number, "numbers of account online: %d", n);
        strcat(mes_list, number);
        strcat(mes_list, "\n");

        while (currentPtr != NULL){ 
            sprintf(money, "%d", currentPtr->data.amount);
            strcat(mes_list, money);
            strcat(mes_list, "\n");            
            strcat(mes_list, currentPtr->data.username);
            strcat(mes_list, " form #");
            strcat(mes_list, currentPtr->data.ipaddr);
            strcat(mes_list, " with port:");
            strcat(mes_list, currentPtr->data.portNum);
            strcat(mes_list, "\n");
            currentPtr = currentPtr->nextPtr;
        }          
        SSL_write(ssl , mes_list , strlen(mes_list));
    }
    return;
}

void delete(char *name, char *pt, char *addr, Linklist **starP){
    Linklist *currentPtr, *previousPtr;
    printf("%s", name);
    printf(" leaves\n");
    previousPtr = NULL;
    currentPtr = *starP;
    while (currentPtr != NULL){
        if (strcmp(currentPtr->data.username, name)==0){
            if (previousPtr == NULL){
                *starP = currentPtr->nextPtr;
            }
            else {
                previousPtr->nextPtr = currentPtr->nextPtr;
            }
            free(currentPtr);
        }
        previousPtr = currentPtr;
        currentPtr = currentPtr->nextPtr;
    }
}

void *connection_handler(void *ssl)
{
    int read_size;
    char *message;
    char buff[MAXBUF]= {0};
    char *registered[2] = {0};
    char *login[2] = {0};
    char *relogin[2] = {0};
    char *deal[3] = {0};
    int times = 0;
    char *mes_name = "Different username! Please retype again!\n";
    char *mes_cn = "The name had existed! Please retype again!\n";
    char *mes_cp = "The port had existed! Please retype again!\n";
    char *mes_error = "Wrong request form.\n";
    char *mes_exit = "Bye!\n";
    char *ok = "Register Successfully\n";
    char *del[3] = {0};
    int checknn;
    int checkpp;
    int count = 0;
    int a = 0;
    Linklist *currentPtr;
    //Send some messages to the client
    message = "Please register frist and then login to get your information!\n";
    SSL_write(ssl , message , strlen(message));
    puts("start");
    a = n;
    //Receive a message from client
    while(1==1)
    {
        int num = 0;
        bzero(buff, sizeof(buff));
        read_size = SSL_read(ssl , buff , sizeof(buff));

        if (strstr(buff, "REGISTER#") != NULL && times == 0){
            char *rebuff = strtok(buff, "#");
            while (rebuff != NULL){
                registered[num++] = rebuff;
                rebuff = strtok(NULL, "#");
            }
            checknn = checkname(registered[1]);
            if (checknn == 0){
                nn[n] = '\0';
                SSL_write(ssl , mes_cn , strlen(mes_cn));
            }
            else{
                nn[n-1] = malloc(sizeof(char)*strlen(registered[1]));
                strcpy(nn[n-1], registered[1]);
                SSL_write(ssl , ok , strlen(ok));
                times++;
            }                
        }

        else if (strstr(buff, registered[1]) != NULL && times == 1){
            char *rebuff = strtok(buff, "#");
            while (rebuff != NULL){
                login[num++] = rebuff;
                rebuff = strtok(NULL, "#");
            }
            if (strstr(login[0], registered[1]) != NULL){
                checkpp = checkport(login[1], startPtr);
                if (checkpp == 0){
                    SSL_write(ssl , mes_cp , strlen(mes_cp));
                }
                else{
                    del[0] = malloc(sizeof(char)*strlen(login[0]));
                    del[1] = malloc(sizeof(char)*strlen(login[1]));
                    del[2] = malloc(sizeof(char)*strlen(ip[n-1]));
                    strcpy(del[0], login[0]);
                    strcpy(del[1], login[1]);
                    strcpy(del[2], ip[n-1]);
                    int a = 10000;
                    add(login[0], login[1], ip[n-1], a, &startPtr);
                    sendlog(ssl, startPtr);
                    times++;
                }                
            }
            else {
                SSL_write(ssl , mes_name , strlen(mes_name));
            }            
        }

        else if (strstr(buff, nn[a-1]) != NULL && count == 0){
            puts("aaaa");
            char *rebuff = strtok(buff, "#");
            while (rebuff != NULL){
                relogin[num++] = rebuff;
                rebuff = strtok(NULL, "#");
            }
            for (int i = 0; i < n; i++){
                if (strcmp(relogin[0], nn[i]) == 0){
                    del[0] = malloc(sizeof(char)*strlen(relogin[0]));
                    del[1] = malloc(sizeof(char)*strlen(relogin[1]));
                    del[2] = malloc(sizeof(char)*strlen(ip[n-1]));
                    strcpy(del[0], relogin[0]);
                    strcpy(del[1], relogin[1]);
                    strcpy(del[2], ip[n-1]);
                    int a = 10000;
                    add(relogin[0], relogin[1], ip[n-1], a, &startPtr);
                    sendlog(ssl, startPtr);
                    count++;
                    n--;
                    break;
                }
            }
        }

        else if (strstr(buff, "List") != NULL && (times == 2 || count == 1)){
            sendlist(ssl, startPtr);
        }

        else if (strstr(buff, "Deal#") != NULL && (times == 2 || count == 1)){ //transaction
            char *rebuff = strtok(buff, "#");
            while (rebuff != NULL){
                deal[num++] = rebuff;
                rebuff = strtok(NULL, "#");
            }
            int yy = atoi(deal[2]);
            //pthread_mutex_lock( &mutex1 );
            plus(deal[1], yy, startPtr);
            printf("%s\n", del[0]);
            reduce(del[0], yy, startPtr);
            sendlist(ssl, startPtr);
            //pthread_mutex_unlock( &mutex1 );
        }

        else if (strstr(buff, "Exit") != NULL){
            SSL_write(ssl , mes_exit , strlen(mes_exit));
            delete(del[0], del[1], del[2], &startPtr);
            n--;
            break;
        }
        
        else {
            SSL_write(ssl , mes_error , strlen(mes_error));
        }
           
    }
    puts("Exit response");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    memset(buff, 0, MAXBUF);

    if(read_size == 0)
    {
        printf("Client disconnected\n");
        //coding
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }
         
    return 0;
}

int main(int argc, char *argv[])
{
    int sockfd, client_sock, c;
    socklen_t len;
    struct sockaddr_in server, client;
    char buf[MAXBUF];
    char new_fileName[50]="/newfile/";
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
    /*---------------------------------------------------------------*/
    /* 開啟一個 socket 監聽 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(1);
    }
    else{
        printf("socket created\n");
    }

    bzero(&server, sizeof(server));
    server.sin_family = PF_INET;
    server.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1)
    {
        perror("bind");
        exit(1);
    }
    else{
        printf("binded\n");
    }

    listen(sockfd , 3);

    printf("Waiting for incoming connections...\n");
    c = sizeof(struct sockaddr_in);
    pthread_t thread_id;

    while ((client_sock = accept(sockfd, (struct sockaddr *)&client, (socklen_t*)&c)))
    {
        SSL *ssl;
        /* 基於 ctx 產生一個新的 SSL */
        ssl = SSL_new(ctx);
        /* 將連線使用者的 socket 加入到 SSL */
        SSL_set_fd(ssl, client_sock);
        /* 建立 SSL 連線 */
        if (SSL_accept(ssl) == -1)
        {
            perror("accept");
            close(client_sock);
            break;
        }

        printf("Connection accepted\n");
        n++;

        if( pthread_create( &thread_id , NULL ,  connection_handler , (void*) ssl) < 0)
        {
            perror("could not create thread");
            return 1;
        }
        ip[n-1] = inet_ntoa(client.sin_addr);
        printf("Handler assigned\n");
    }
    if (client_sock < 0){
        perror("accept failed");
        return 1;
    }

    SSL_CTX_free(ctx);

    return 0;
}