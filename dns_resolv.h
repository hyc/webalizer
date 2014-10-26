#ifndef _DNS_RESOLV_H
#define _DNS_RESOLV_H

#ifdef USE_DNS    /* skip whole file if not using DNS stuff...             */

struct dnsRecord { time_t    timeStamp;       /* Timestamp of resolv data  */
                   int       numeric;         /* 0: Name, 1: IP-address    */
                   char      hostName[1]; };  /* Hostname (var length)     */

struct dns_child             /* Defines the communication with a DNS child */
{
  int inpipe[2];             /* Pipe Child  -> Father */
  int outpipe[2];            /* Pipe Father -> Child */
  int pid;                   /* PID of Child */
  int flags;                 /* see below */
  struct dnode *cur;         /* Currently processed node */
};

extern void resolve_dns(struct log_struct *);
extern DB   *dns_db;
extern int  dns_fd;
extern int  dns_resolver(void *);
extern int  open_cache();
extern int  close_cache();

extern DB   *geo_db;
extern DB   *geodb_open(char *);
extern char *geodb_ver(DB *, char *);
extern char *geodb_get_cc(DB *, char *, char *);
extern void  geodb_close(DB *);

#define DNS_CHILD_READY   0x1         /* Our child flags                    */
#define DNS_CHILD_RUNNING 0x2

#define MAXCHILD          100         /* Maximum number of DNS children     */

#ifndef GEODB_LOC
#define GEODB_LOC "/usr/share/GeoDB"
#endif

#endif  /* USE_DNS */
#endif  /* _DNS_RESOLV_H */
