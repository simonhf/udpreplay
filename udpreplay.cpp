/*
Copyright (c) 2016 Erik Rigtorp <erik@rigtorp.se>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#include <cstring>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
  static const char usage[] =
      " [-i iface] [-l] [-s speed] [-t ttl] pcap\n"
      "\n"
      "  -i iface    interface to send packets through\n"
      "  -l          enable loopback\n"
      "  -s speed    replay speed relative to pcap timestamps\n"
      "  -d delay    usec; e.g. 1,000 is 1 ms\n"
      "  -f freq     delay every <freq> packets sent\n"
      "  -g group    group <group> packets together, e.g. 1 or 6\n"
      "  -r          repeat at end of pcap file\n"
      "  -t ttl      packet ttl";

  int ifindex = 0;
  int loopback = 0;
  //double speed = 1;
  int ttl = -1;
  int delay  = 100; // 0.1 ms
  int freq   =  50; // delay every 50 packets
  int repeat =   0;
  int group  =   1;

  int opt;
  while ((opt = getopt(argc, argv, "i:ls:t:rd:f:g:")) != -1) {
    switch (opt) {
    case 'i':
      ifindex = if_nametoindex(optarg);
      if (ifindex == 0) {
        std::cerr << "if_nametoindex: " << strerror(errno) << std::endl;
        return 1;
      }
      break;
    case 'l':
      loopback = 1;
      break;
    case 'r':
      repeat = 1;
      break;
    //case 's':
    //  speed = std::stod(optarg);
    //  break;
    case 'd':
      delay = std::stoi(optarg);
      break;
    case 'f':
      freq = std::stoi(optarg);
      break;
    case 'g':
      group = std::stoi(optarg);
      break;
    case 't':
      ttl = std::stoi(optarg);
      break;
    default:
      std::cerr << "usage: " << argv[0] << usage << std::endl;
      return 1;
    }
  }
  if (optind >= argc) {
    std::cerr << "usage: " << argv[0] << usage << std::endl;
    return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return 1;
  }

  if (ifindex != 0) {
    ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) ==
        -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (loopback != 0) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback,
                   sizeof(loopback)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (ttl != -1) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  time_t last_time = time(NULL);
  REPEAT:;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(argv[optind], errbuf);
  if (handle == nullptr) {
    std::cerr << "pcap_open: " << errbuf << std::endl;
    return 1;
  }

  pcap_pkthdr header;
  const u_char *p;
  timeval tv = {0, 0};
  unsigned long count = 0;
  unsigned long sent  = 0;
  unsigned long last_count = 0;
  unsigned long last_sent  = 0;
#define JUMBO_MAX_BYTES (9001)
  char jumbo[JUMBO_MAX_BYTES];
  int  jumbo_appends = 0;
  int  jumbo_used    = 0;
  printf("- starting sending loop\n");
  while ((p = pcap_next(handle, &header))) {
    p += 2; // see https://www.eecis.udel.edu/~sunshine/expcs/code/pcap_packet_read.c
    if (header.len != header.caplen) {
      continue;
    }
    auto eth = reinterpret_cast<const ether_header *>(p);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
      continue;
    }
    auto ip = reinterpret_cast<const iphdr *>(p + sizeof(ether_header));
    if (ip->version != 4) {
      continue;
    }
    if (ip->protocol != IPPROTO_UDP) {
      continue;
    }
    auto udp = reinterpret_cast<const udphdr *>(p + sizeof(ether_header) +
                                                ip->ihl * 4);

    if (tv.tv_sec == 0) {
      tv = header.ts;
    }
    timeval diff;
    timersub(&header.ts, &tv, &diff);
    //do not use original timings usleep((diff.tv_sec * 1000000 + diff.tv_usec) * speed);

    ssize_t len = ntohs(udp->len) - 8;
    const u_char *d = &p[sizeof(ether_header) + ip->ihl * 4 + sizeof(udphdr)];

    if(jumbo_used + len > JUMBO_MAX_BYTES){ printf("ERROR: jumbo overflow detected!\n"); exit(0); }
    memcpy(&jumbo[jumbo_used], d, len);
    jumbo_appends ++;
    jumbo_used    += len;
    if(jumbo_appends == group) { // 6 for MTU 9,001 byte packet

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = udp->dest;
    //addr.sin_addr = {ip->daddr};
    addr.sin_addr.s_addr = inet_addr("10.130.18.8"); // force send packets to this IP!
    auto n = sendto(fd, &jumbo[0], jumbo_used, 0, reinterpret_cast<sockaddr *>(&addr),
                    sizeof(addr));
    if (n != jumbo_used) {
      std::cerr << "sendto: " << strerror(errno) << std::endl;
      return 1;
    }
    sent += jumbo_used;
    if ((++ count % 100) == 0) { time_t this_time = time(NULL); if(this_time != last_time) { last_time = this_time; printf("- sent %lu bytes in %lu packets\n", sent - last_sent, count - last_count); last_sent = sent; last_count = count; }}
    if ((count % freq) == 0) { usleep(delay); } // delay=100 means sleep for 0.1 ms
    //if (count == 152) { exit(0); }

    jumbo_appends = 0;
    jumbo_used    = 0;
    }
  }
  printf("- sent %lu bytes in %lu packets total\n", sent, count);

  if (repeat) { pcap_close(handle); goto REPEAT; }

  return 0;
}
