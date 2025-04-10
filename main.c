#include <stdio.h>
#include "packet_reading.h"

int main(int argc, char *argv[]){
  
  parse_pcap(argv[1]);
  printf("\n");
  return 0;
    

}
