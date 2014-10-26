/*
    webalizer - a web server log analysis program

    Copyright (C) 1997-2013  Bradford L. Barrett

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version, and provided that the above
    copyright and permission notice is included with all distributed
    copies of this or derived software.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

*/

/*********************************************/
/* STANDARD INCLUDES                         */
/*********************************************/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>                           /* normal stuff             */
#include <ctype.h>
#include <sys/utsname.h>
#include <zlib.h>

/* ensure sys/types */
#ifndef _SYS_TYPES_H
#include <sys/types.h>
#endif

/* Need socket header? */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

/* some systems need this */
#ifdef HAVE_MATH_H
#include <math.h>
#endif

#ifdef USE_DNS                   /* skip everything in this file if no DNS */

#include <netinet/in.h>          /* include stuff we need for dns lookups, */
#include <arpa/inet.h>           /* DB access, file control, etc...        */
#include <fcntl.h>
#include <netdb.h>               /* ensure getaddrinfo/getnameinfo         */
#include <signal.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <db.h>                                /* DB header ****************/
#include "webalizer.h"                         /* main header              */
#include "lang.h"                              /* language declares        */
#include "hashtab.h"                           /* hash table functions     */
#include "parser.h"                            /* log parser functions     */
#include "dns_resolv.h"                        /* our header               */

/* local data */

DB       *dns_db   = NULL;                     /* DNS cache database       */
int      dns_fd    = 0;

DB       *geo_db   = NULL;                     /* GeoDB database           */
DBC      *geo_dbc  = NULL;                     /* GeoDB database cursor    */

struct   dns_child child[MAXCHILD];            /* DNS child pipe data      */

DNODEPTR host_table[MAXHASH];                  /* hostname/ip hash table   */

char     buffer[BUFSIZE];                      /* log file record buffer   */
char     tmp_buf[BUFSIZE];                     /* used to temp save above  */
struct   utsname system_info;                  /* system info structure    */

int      raiseSigChild = 1;

time_t runtime;
time_t start_time, end_time;
float  temp_time;

extern char *our_gzgets(void *, char *, int);  /* external our_gzgets func */

/* internal function prototypes */

static void process_list(DNODEPTR);
static void sigChild(int);
static void db_put(char *, char *, int);
void   set_fl(int, int);
void   clr_fl(int, int);
int    iptype(char *, unsigned char *);

/*********************************************/
/* RESOLVE_DNS - lookup IP in cache          */
/*********************************************/

void resolve_dns(struct log_struct *log_rec)
{
   DBT    query, response;
   int    i;
   /* aligned dnsRecord to prevent Solaris from doing a dump */
   /* (not found in debugger, as it can dereference it :(    */
   struct dnsRecord alignedRecord;

   if (!dns_db) return;   /* ensure we have a dns db */

   memset(&query, 0, sizeof(query));
   memset(&response, 0, sizeof(response));
   query.data = log_rec->hostname;
   query.size = strlen(log_rec->hostname);

   if (debug_mode) fprintf(stderr,"Checking %s...", log_rec->hostname);

   if ( (i=dns_db->get(dns_db, NULL, &query, &response, 0)) == 0)
   {
      memcpy(&alignedRecord, response.data, sizeof(struct dnsRecord));
      strncpy (log_rec->hostname,
               ((struct dnsRecord *)response.data)->hostName,
               MAXHOST);
      log_rec->hostname[MAXHOST-1]=0;
      if (debug_mode)
         fprintf(stderr," found: %s (%ld)\n",
           log_rec->hostname, alignedRecord.timeStamp);
   }
   else  /* not found or error occured during get */
   {
      if (debug_mode)
      {
         if (i==DB_NOTFOUND) fprintf(stderr," not found\n");
         else                fprintf(stderr," error (%d)\n",i);
      }
   }
}

/*********************************************/
/* DNS_RESOLVER - read log and lookup IP's   */
/*********************************************/

int dns_resolver(void *log_fp)
{
   DNODEPTR  h_entries;
   DNODEPTR  l_list = NULL;

   int       i;
   int       save_verbose=verbose;

   u_int64_t listEntries = 0;

   struct sigaction sigPipeAction;
   struct stat dbStat;
   /* aligned dnsRecord to prevent Solaris from doing a dump */
   /* (not found in debugger, as it can dereference it :(    */
   struct dnsRecord alignedRecord;

   struct    flock tmp_flock;

   tmp_flock.l_whence=SEEK_SET;    /* default flock fields */
   tmp_flock.l_start=0;
   tmp_flock.l_len=0;
   tmp_flock.l_pid=0;

   time(&runtime);

   /* get processing start time */
   start_time = time(NULL);

   /* minimal sanity check on it */
   if(stat(dns_cache, &dbStat) < 0)
   {
      if(errno != ENOENT)
      {
         dns_cache=NULL;
         dns_db=NULL; return 0;  /* disable cache */
      }
   }
   else
   {
      if(!dbStat.st_size)  /* bogus file, probably from a crash */
      {
         unlink(dns_cache);  /* remove it so we can recreate... */
      }
   }
  
   /* open cache file */
   if ( (db_create(&dns_db, NULL, 0) != 0)   ||
        (dns_db->open(dns_db, NULL,
           dns_cache, NULL, DB_HASH,
           DB_CREATE, 0644) != 0) )
   {
      /* Error: Unable to open DNS cache file <filename> */
      if (verbose) fprintf(stderr,"%s %s\n",msg_dns_nodb,dns_cache);
      dns_cache=NULL;
      dns_db=NULL;
      return 0;                  /* disable cache */
   }

   /* get file descriptor */
   dns_db->fd(dns_db, &dns_fd);

   tmp_flock.l_type=F_WRLCK;                    /* set read/write lock type */
   if (fcntl(dns_fd,F_SETLK,&tmp_flock) < 0)    /* and barf if we cant lock */
   {
      /* Error: Unable to lock DNS cache file <filename> */
      if (verbose) fprintf(stderr,"%s %s\n",msg_dns_nolk,dns_cache);
      dns_db->close(dns_db, 0);
      dns_cache=NULL;
      dns_db=NULL;
      return 0;                  /* disable cache */
   }

   /* Setup signal handlers */
   sigPipeAction.sa_handler = SIG_IGN;
   sigPipeAction.sa_flags   = SA_RESTART;
   sigemptyset(&sigPipeAction.sa_mask);

   sigaction(SIGPIPE, &sigPipeAction, NULL);

   /* disable warnings/errors for this run... */
   verbose=0;

   /* Main loop to read log records (either regular or zipped) */
   while ( (gz_log)?(our_gzgets((void *)log_fp,buffer,BUFSIZE) != Z_NULL):
           (fgets(buffer,BUFSIZE,log_fname?(FILE *)log_fp:stdin) != NULL))
   {
      if (strlen(buffer) == (BUFSIZE-1))
      {
         /* get the rest of the record */
         while ( (gz_log)?(our_gzgets((void *)log_fp,buffer,BUFSIZE)!=Z_NULL):
                 (fgets(buffer,BUFSIZE,log_fname?(FILE *)log_fp:stdin)!=NULL))
         {
            if (strlen(buffer) < BUFSIZE-1) break;
         }
         continue;                        /* go get next record if any    */
      }

      strcpy(tmp_buf, buffer);            /* save buffer in case of error */
      if(parse_record(buffer))            /* parse the record             */
      {
         struct addrinfo hints, *ares;
         memset(&hints, 0, sizeof(hints));
         hints.ai_family   = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         hints.ai_flags    = AI_NUMERICHOST;
         if (0 == getaddrinfo(log_rec.hostname, "0", &hints, &ares))
         {
            DBT q, r;
            memset(&q, 0, sizeof(q));
            memset(&r, 0, sizeof(r));
            q.data = log_rec.hostname;
            q.size = strlen(log_rec.hostname);

            /* Check if we have it in DB */
            if ( (i=dns_db->get(dns_db, NULL, &q, &r, 0)) == 0 )
            {
               /* have a record for this address */
               memcpy(&alignedRecord, r.data, sizeof(struct dnsRecord));
               if (alignedRecord.timeStamp != 0)
                  /* If it's not permanent, check if it's TTL has expired */
                  if ( (runtime-alignedRecord.timeStamp ) > (86400*cache_ttl) )
                     put_dnode(log_rec.hostname, ares->ai_addr,
                               ares->ai_addrlen,  host_table);
            }
            else
            {
               if (i==DB_NOTFOUND)
                   put_dnode(log_rec.hostname, ares->ai_addr,
                             ares->ai_addrlen, host_table);
            }
            freeaddrinfo(ares);
         }
      }
   }
   verbose = save_verbose;     /* restore verbosity level... */

   listEntries = 0;
  
   /* build our linked list l_list  */
   for(i=0;i < MAXHASH; i++)
   {
      for(h_entries=host_table[i]; h_entries ; h_entries = h_entries->next)
      {
         h_entries->llist = l_list;
         l_list = h_entries;
         listEntries++;
      }
   }

   if(!l_list)
   {
      /* No valid addresses found... */
      if (verbose>1) printf("%s\n",msg_dns_none);
      tmp_flock.l_type=F_UNLCK;
      fcntl(dns_fd, F_SETLK, &tmp_flock);
      dns_db->close(dns_db, 0);
      return 0;
   }

   /* process our list now... */
   process_list(l_list);

   /* get processing end time */
   end_time = time(NULL);

   /* display DNS processing statistics */
   if (time_me || (verbose>1))
   {
      if (verbose<2 && time_me) printf("DNS: ");
      printf("%llu %s ",listEntries, msg_addresses);

      /* total processing time in seconds */
      temp_time = difftime(end_time,start_time);
      if (temp_time==0) temp_time=1;
      printf("%s %.0f %s", msg_in, temp_time, msg_seconds);

      /* calculate records per second */
      if (temp_time)
         i=( (int)((float)listEntries/temp_time) );
      else i=0;

      if ( (i>0) && (i<=listEntries) ) printf(", %d/sec\n", i);
         else  printf("\n");
   }

   /* processing done, exit   */
   tmp_flock.l_type=F_UNLCK;
   fcntl(dns_fd, F_SETLK, &tmp_flock);
   dns_db->close(dns_db, 0);
   return 0;

}

/*********************************************/
/* PROCESS_LIST - do the resoluton...        */
/*********************************************/

static void process_list(DNODEPTR l_list)
{
   DNODEPTR  trav;

   char   child_buf[MAXHOST+3-((unsigned long)&trav+sizeof(trav))%3];
   char   dns_buf[MAXHOST];
   int    i;
   int    pid;
   int    nof_children = 0;
   fd_set rd_set;
   char   hbuf[NI_MAXHOST];
  
   struct sigaction sigChildAction;
  
   sigChildAction.sa_handler = sigChild;
   sigChildAction.sa_flags   = SA_NOCLDSTOP|SA_RESTART;
   sigemptyset(&sigChildAction.sa_mask);

   raiseSigChild = 0;
  
   sigaction(SIGCHLD, &sigChildAction, NULL);
  
   /* fire up our child processes */
   for(i=0; i < dns_children; i++)
   {
      if(pipe(child[i].inpipe))
      {
         if (verbose) fprintf(stderr,"INPIPE creation error");
         return;   /* exit(1) */
      }

      if(pipe(child[i].outpipe))
      {
         if (verbose) fprintf(stderr,"OUTPIPE creation error");
         return;   /* exit(1); */
      }

      /* fork it off */
      switch(pid=fork())
      {
         case -1:
         {
            if (verbose) fprintf(stderr,"FORK error");
            return;  /* exit(1); */
         }
	  
         case 0:             /* Child */
         {
            int size;

            close(child[i].inpipe[0]);
            close(child[i].outpipe[1]);

            /* get struct sockaddr_storage here */
            while((size = read(child[i].outpipe[0], child_buf, MAXHOST)))
            {
               if(size < 0)
               {
                  perror("read error");
                  exit(1);
               }
               else
               {
                  /* Clear out our buffer */
                  memset(hbuf,0,NI_MAXHOST);

                  if(0 == getnameinfo((struct sockaddr*)child_buf, size,
                                     hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD))
                  {
                     /* must be at least 4 chars */
                     if (strlen(hbuf)>3)
                     {
                        /* If long hostname, take max domain name part */
                        if ((size = strlen(hbuf)) > MAXHOST-2)
                           strcpy(child_buf,(hbuf+(size-MAXHOST+1)));
                        else strcpy(child_buf, hbuf);
                        size = strlen(child_buf);
                     }
                     else
                     {
                        if (debug_mode)
                           printf("Child %d getnameinfo bad hbuf!\n",i);
                     }
                  }
                  else
                  {
                     if(debug_mode)
                       printf("Child %d getnameinfo failed!\n",i);
                  }

                  if (write(child[i].inpipe[1], child_buf, size) == -1)
                  {
                     perror("write error");
                     exit(1);
                  }
               }
            }
            close(child[i].inpipe[1]);
            close(child[i].outpipe[0]);
		
            if(debug_mode)
               printf( "Child %d got closed input, shutting down\n", i);  

            fflush(stdout);
            exit(0);
         }  /* case 0 */
		
         default:
         {
            child[i].pid = pid;
            child[i].flags = DNS_CHILD_READY|DNS_CHILD_RUNNING;
            nof_children++;
            close(child[i].inpipe[1]);
            close(child[i].outpipe[0]);

            set_fl(child[i].inpipe[0], O_NONBLOCK);
         }
      }
   }

   trav = l_list;

   while(nof_children)
   {
      static struct timeval selectTimeval;
      int res;
      int max_fd;
	  
      FD_ZERO(&rd_set);
      max_fd = 0;

      if(raiseSigChild)
      {
         int pid;

         while((pid = waitpid(-1, NULL, WNOHANG)) > 0)
         {
            for(i=0;i<dns_children;i++)
            {
               if(child[i].pid == pid)
               {
                  child[i].pid = 0;
                  child[i].flags &= ~(DNS_CHILD_READY|DNS_CHILD_RUNNING);
                  nof_children--;

                  if(debug_mode)
                  printf("Reaped Child %d\n", pid);

                  break;
               }
            }
         }
         raiseSigChild--;
         continue; /* while, nof children has just changed */
      }

      for(i=0;i<dns_children;i++)
      {
         if(child[i].flags & DNS_CHILD_RUNNING) /* Child is running */
         {
            if(child[i].flags & DNS_CHILD_READY)
            {
               child[i].flags  &= ~DNS_CHILD_READY;

               if(trav)  /* something to resolve */
               {
                  if (write(child[i].outpipe[1], &trav->addr,
                     trav->addrlen) != -1)
                  {
                     /* We will watch this child */
                     child[i].cur    = trav;
                     FD_SET(child[i].inpipe[0], &rd_set);
                     max_fd = MAX(max_fd, child[i].inpipe[0]);

                     if(debug_mode)
                        printf("Giving %d bytes to Child %d\n",
                        trav->addrlen, i);

                     trav = trav->llist;
                  }
                  else  /* write error */
                  {
                     if(errno != EINTR)           /* Could be a signal */
                     {
                        perror("Could not write to pipe");
                        close(child[i].outpipe[1]);           /* kill     */
                        child[i].flags &= ~DNS_CHILD_RUNNING; /* child    */
                     }
		  }
               }
               else /* List is complete */
               {
                  close(child[i].outpipe[1]);            /* Go away       */
                  child[i].flags &= ~DNS_CHILD_RUNNING;  /* Child is dead */
               }
            }
            else
            {
               /* Look, the busy child... */
               FD_SET(child[i].inpipe[0], &rd_set);
               max_fd = MAX(max_fd, child[i].inpipe[0]);
            }
         }
      }

      selectTimeval.tv_sec =  5; /* This stuff ticks in 5 second intervals */
      selectTimeval.tv_usec = 0;

      switch(res = select(max_fd+1, &rd_set, NULL, NULL, &selectTimeval))
      {
         case -1:
         {
            if(errno != EINTR)   /* Could be a signal */
            perror("Error in select");

            break;
         }

         case 0:   /* Timeout, just fall once through the child loop */
         {
            if(debug_mode)
            printf("tick\n");
		
            break;
         }

         default:
         {
            for(i=0; i< dns_children;i++)
            {
               if(!res)   /* All file descriptors done */
               break;

               if(FD_ISSET(child[i].inpipe[0], &rd_set))
               {
                  int size;

                  res--;  /* One less... */

                  switch (size=read(child[i].inpipe[0], dns_buf, MAXHOST))
                  {
                     case -1:
                     {
                        if(errno != EINTR)
                        perror("Could not read from pipe");
                        break;
                     }
                     case 0:
                     {
                        /* EOF. Child has closed Pipe. It shouldn't have */
                        /*  done that, could be an error or something.   */
                        /*  Reap it                                      */
                        close(child[i].outpipe[1]);
                        child[i].flags &= ~DNS_CHILD_RUNNING;

                        if(debug_mode)
                           printf("Child %d wants to be reaped\n", i);

                        break;
                     }

                     default:
                     {
                        dns_buf[size] = '\0';
                        if( strlen(dns_buf) > 1 &&
                             memcmp(dns_buf, &(child[i].cur->addr),
                                    sizeof(child[i].cur->addr)))
                        {
                           if(debug_mode)
                              printf("Child %d Got a result: %s -> %s\n",
                                     i, child[i].cur->string, dns_buf);
                           db_put(child[i].cur->string, dns_buf, 0);
                        }
                        else
                        {
                           if(debug_mode)
                              printf("Child %d could not resolve: %s (%s)\n",
                                     i, child[i].cur->string,
                                     (cache_ips)?"cache":"no cache");
                           if (cache_ips)      /* Cache non-resolved? */
                              db_put(child[i].cur->string,
                                     child[i].cur->string,1);
                        }

                        if(debug_mode)
                           printf("Child %d back in task pool\n", i);

                        /* Child is back in the task pool */
                        child[i].flags |= DNS_CHILD_READY;
                        break;
                     }
                  }
               }
            }
            break;
         }
      }
   }
   return;
}

/*********************************************/
/* SET_FL - set flag on pipe FD              */
/*********************************************/

void set_fl(int fd, int flags)
{
   int val;

   /* get current flags */
   if ((val=fcntl(fd, F_GETFL, 0)) < 0)
      if (verbose) fprintf(stderr,"set_fl F_GETFL error\n");

   /* set them */
   val |= flags;

   /* and write them back */
   if ((val=fcntl(fd, F_SETFL, val)) < 0)
      if (verbose) fprintf(stderr,"set_fl F_SETFL error\n");
}

/*********************************************/
/* CLR_FL - clear flag on pipe FD            */
/*********************************************/

void clr_fl(int fd, int flags)
{
   int val;

   /* Get current flags */
   if ((val=fcntl(fd, F_GETFL, 0)) < 0)
      if (verbose) fprintf(stderr,"clr_fl F_GETFL error\n");

   /* set them */
   val &= ~flags;

   /* and write them back */
   if ((val=fcntl(fd, F_SETFL, val)) < 0)
      if (verbose) fprintf(stderr,"clr_fl F_SETFL error\n");
}

/*********************************************/
/* DB_PUT - put key/val in the cache db      */
/*********************************************/

static void db_put(char *key, char *value, int numeric)
{
   DBT    k, v;
   char   *cp;
   struct dnsRecord *recPtr = NULL;
   int    nameLen = strlen(value)+1;

   /* Align to multiple of eight bytes */
   int recSize = (sizeof(struct dnsRecord)+nameLen+7) & ~0x7;
	
   /* make sure we have a db ;) */
   if(dns_db)
   {
      if((recPtr = calloc(1, recSize)))
      {
         recPtr->timeStamp = runtime;
         recPtr->numeric = numeric;
         memcpy(&recPtr->hostName, value, nameLen);
         memset(&k, 0, sizeof(k));
         memset(&v, 0, sizeof(v));

         /* Ensure all data is lowercase */
         cp=key;   while (*cp++!='\0') *cp=tolower(*cp);
         cp=value; while (*cp++!='\0') *cp=tolower(*cp);

         k.data = key;
         k.size = strlen(key);

         v.size = recSize;
         v.data = recPtr;

         if ( dns_db->put(dns_db, NULL, &k, &v, 0) != 0 )
            if (verbose>1) fprintf(stderr,"db_put fail!\n");
         free(recPtr);
      }
   }
}

/*********************************************/
/* SIGCHILD - raise our signal               */
/*********************************************/

static void sigChild(int signum)
{
   raiseSigChild++;
}

/*********************************************/
/* OPEN_CACHE - open our cache file RDONLY   */
/*********************************************/

int open_cache()
{
   struct stat  dbStat;
   struct flock tmp_flock;

   tmp_flock.l_whence=SEEK_SET;    /* default flock fields */
   tmp_flock.l_start=0;
   tmp_flock.l_len=0;
   tmp_flock.l_pid=0;
   tmp_flock.l_type=F_RDLCK;

   /* double check filename was specified */
   if(!dns_cache) { dns_db=NULL; return 0; }

   /* minimal sanity check on it */
   if(stat(dns_cache, &dbStat) < 0)
   {
      if(errno != ENOENT) return 0;
   }
   else
   {
      if(!dbStat.st_size)  /* bogus file, probably from a crash */
      {
         unlink(dns_cache);  /* remove it so we can recreate... */
      }
   }
  
   /* open cache file */
   if ( (db_create(&dns_db, NULL, 0) != 0)   ||
        (dns_db->open(dns_db, NULL,
           dns_cache, NULL, DB_HASH,
           DB_RDONLY, 0644) != 0) )
   {
      /* Error: Unable to open DNS cache file <filename> */
      if (verbose) fprintf(stderr,"%s %s\n",msg_dns_nodb,dns_cache);
      return 0;                  /* disable cache */
   }

   /* get file descriptor */
   dns_db->fd(dns_db, &dns_fd);

   /* Get shared lock on cache file */
   if (fcntl(dns_fd, F_SETLK, &tmp_flock) < 0)
   {
      if (verbose) fprintf(stderr,"%s %s\n",msg_dns_nolk,dns_cache);
      dns_db->close(dns_db, 0);
      return 0;
   }
   return 1;
}

/*********************************************/
/* CLOSE_CACHE - close our RDONLY cache      */
/*********************************************/

int close_cache()
{
   struct flock tmp_flock;

   tmp_flock.l_whence=SEEK_SET;    /* default flock fields */
   tmp_flock.l_start=0;
   tmp_flock.l_len=0;
   tmp_flock.l_pid=0;
   tmp_flock.l_type=F_UNLCK;

   /* clear lock and close cache file */
   fcntl(dns_fd, F_SETLK, &tmp_flock);
   dns_db->close(dns_db, 0);
   return 1;
}

/*********************************************/
/* GEODB_OPEN - Open GeoDB database/cursor   */
/*********************************************/

DB *geodb_open(char *dbname)
{
   char buf[1025];

   if (dbname==NULL)
      snprintf(buf,sizeof(buf),"%s/GeoDB.dat",GEODB_LOC);
   else
      strncpy(buf,dbname,sizeof(buf)-1);
   buf[sizeof(buf)-1]='\0';

   /* create database thingie */
   if ( db_create(&geo_db, NULL, 0) ) return NULL;

   /* open the database */
   if (geo_db->open(geo_db,NULL,buf,NULL,DB_BTREE,DB_RDONLY,0)) return NULL;

   /* create our cursor */
   if (geo_db->cursor(geo_db,NULL,&geo_dbc,0))
   {
      geo_db->close(geo_db,0);
      return NULL;
   }
   /* all is well in the world */
   return geo_db;
}

/*********************************************/
/* GEODB_VER - Get database version info     */
/*********************************************/

char *geodb_ver(DB *db, char *str)
{
   int       i;
   DBT       k,v;
   unsigned  char x[16];

   memset(&x,   0, sizeof(x));
   memset(&k,   0, sizeof(k));
   memset(&v,   0, sizeof(v));
   k.data=&x;
   k.size=sizeof(x);

   i=geo_db->get(geo_db, NULL, &k, &v, 0);

   if (i) strncpy(str, "Unknown", 8);
   else   strncpy(str, v.data+3, v.size-3);
   return str;
}

/*********************************************/
/* GEODB_GET_CC - Get country code for IP    */
/*********************************************/

char *geodb_get_cc(DB *db, char *ip, char *buf)
{
   int      i;
   DBT      k,v;
   unsigned char addr[16];

   memset(addr, 0, sizeof(addr));
   strncpy(buf, "--", 3);

   /* get IP address */
   if (!iptype(ip, addr)) return buf;

   /* kludge for IPv6 mapped IPv4 */
   if (addr[0]==0 && addr[1]==0 && addr[2]==0) { addr[10]=0; addr[11]=0; }

   /* kludge for IPv6 6to4 (RFC3056) */
   if (addr[0]==0x20 && addr[1]==0x02)
   {
      memcpy(&addr[12],&addr[2],4);
      memset(&addr,0,12);
   }

   memset(&k, 0, sizeof(k));
   memset(&v, 0, sizeof(v));
   k.data=&addr;
   k.size=sizeof(addr);

   i=geo_dbc->c_get(geo_dbc, &k, &v, DB_SET_RANGE);
   if (!i) memcpy(buf, v.data, 2);
   return buf;
}

/*********************************************/
/* GEODB_CLOSE - close GeoDB database        */
/*********************************************/

void geodb_close(DB *db)
{
   db->close(db,0);
}

/*********************************************/
/* IPTYPE - get IP type and format addr buf  */
/*********************************************/

int iptype(char *ip, unsigned char *buf)
{
   if (inet_pton(AF_INET6, ip, buf)>0)     return 2;
   if (inet_pton(AF_INET,  ip, buf+12)>0)  return 1;
   else return 0;
}

#endif  /* USE_DNS */
