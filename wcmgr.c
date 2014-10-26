/*
    wcmgr - Webalizer (DNS) Cache file Manager

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
#include <locale.h>

#ifndef USE_DNS

/* ********************************************************** */
/* If DNS support is not enabled, then we just compile a stub */
/* program that displays an appropriate warning when run.     */
/* ********************************************************** */

int main()
{
   printf("********************* NOTICE!! *********************\n");
   printf("This version of the Webalizer was not compiled with\n");
   printf("DNS support.  In order to use this program, you must\n");
   printf("configure the Webalizer at build time with the DNS\n");
   printf("support enabled (--enable-dns configure option).\n");
   printf("****************************************************\n\n");
   exit(1);   /* exit with error code */
}

#else /* USE_DNS defined */

#include <errno.h>
#include <unistd.h>                           /* normal stuff             */
#include <fcntl.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <sys/stat.h>

/* ensure getopt    */
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

/* ensure sys/types */
#ifndef _SYS_TYPES_H
#include <sys/types.h>
#endif

#include <db.h>
#include "webalizer.h"

/* Stupid pre-processor tricks */
#define xstr(x) #x
#define str(x) xstr(x)
#define SMAXHOST str(MAXHOST)   /* String version of MAXHOST value */

/*********************************************/
/* Forward reference local functions         */
/*********************************************/

void list_cache(void);
void stat_cache(void);
void export_cache(void);
void import_cache(void);
void find_rec(void);
void add_rec(void);
void del_rec(void);
void purge_cache(void);
void create_cache(void);
static int db_put(char *, char *, int, time_t);

/*********************************************/
/* GLOBAL VARIABLES                          */
/*********************************************/

char    *pname       = "WCMGR - Webalizer (DNS) Cache file Manager";
char    *version     = "1.00";             /* program version             */
char    *editlvl     = "04";               /* edit level                  */
char    *moddate     = "26-Aug-2013";      /* modification date           */
char    *copyright   = "Copyright 2007-2013 by Bradford L. Barrett";

int       action     = 'l';                /* action flag (default=list)  */
int       create     = 0;                  /* cache creation flag         */
int       verbose    = 0;                  /* Verbose flag (1=be verbose) */
int       rec_ttl    = 7;                  /* purge TTL in days           */
DB        *dns_db    = NULL;               /* DNS cache database          */
DB        *out_db    = NULL;               /* output cache db if needed   */
DBC       *cursorp   = NULL;               /* database cursor             */
DBT       q, r;                            /* query/reply structures      */
char      *in_file   = NULL;               /* input cache filename        */
char      out_file[MAXHOST+4];             /* output cache filename       */
int       dns_fd     = 0;                  /* database file descriptor    */
time_t    runtime;                         /* runtime for TTL calcs       */
char      addr[129];                       /* buffer for IP search addr   */
char      name[MAXHOST+1];                 /* buffer for name value       */

extern char  *optarg;                      /* command line processing     */
extern int   optind;
extern int   opterr;

/* dnsRecord structure used in wcmgr */
struct dnsRec
       {
          time_t    timeStamp;             /* Timestamp of resolv data    */
          int       numeric;               /* 0: Name, 1: IP-address      */
          char      hostName[MAXHOST+1];   /* Hostname buffer (variable)  */
       } dns_rec;

#define DNSZ sizeof(struct dnsRec)         /* define static record size   */

/*********************************************/
/* PRINT_VER - display version information   */
/*********************************************/

void print_ver()
{
   int v,r,l;
   struct utsname system_info;
   uname(&system_info);
   printf("%s V%s-%s\n%s\n",pname,version,editlvl,copyright);
   if (verbose)
   {
      db_version(&v,&r,&l);
      printf("System  : %s %s (%s)\n",
             system_info.sysname,
             system_info.release,
             system_info.machine);
      printf("DB Ver. : V%d.%d.%d\n",v,r,l);
      printf("Mod Date: %s\n",moddate);
   }
   printf("\n");
   exit(0);
}

/*********************************************/
/* PRINT_HELP - Command help display         */
/*********************************************/

void print_help(void)
{
   printf("Usage: wcmgr [options] cache-file\n\n");
   printf("Options:\n");
   printf(" -h         This help display\n");
   printf(" -V         Version information\n");
   printf(" -v         be verbose\n");
   printf(" -a addr    Add DNS record\n");
   printf(" -c         Create new cache file\n");
   printf(" -d addr    Delete DNS record\n");
   printf(" -f addr    Find DNS record\n");
   printf(" -i name    Import cache from file\n");
   printf(" -l         List cache file contents\n");
   printf(" -n name    hostname (used for add)\n");
   printf(" -p num     Purge after num days\n");
   printf(" -s         Display cache file stats/info\n");
   printf(" -t num     TTL value (for add and stats)\n");
   printf(" -x name    Export cache to tab file\n");
   printf("\n");
   printf("If no options are specified, the default\n");
   printf("action is to list the cache file contents.\n\n");
   exit(0);
}

/*********************************************/
/* TTL_AGE - format TTL age for printing     */
/*********************************************/

const char *ttl_age(time_t now, time_t then)
{
   static   char our_buffer[32];         /* string return buffer      */
   time_t   age;                         /* age value in seconds      */
   int      days, hours, mins;           /* day/hour/min counters     */

   /* get age in seconds */
   age=now-then;

   /* now calc days/hours/min */
   days=age/86400;   age=age-(days*86400);
   hours=age/3600;   age=age-(hours*3600);
   mins=age/60;

   /* format the string */
   sprintf(our_buffer,"%02dd:%02dh:%02dm",days, hours, mins);

   /* and return to caller */
   return our_buffer;
}

/*********************************************/
/* MAIN entry point here                     */
/*********************************************/

int main(int argc, char *argv[])
{
   int       i;                          /* gotta have one of these :-)     */

   /* some systems need this */
   setlocale(LC_CTYPE,"");

   /* initalize name/addr */
   memset(addr, 0, sizeof(addr));
   memset(name, 0, sizeof(name));
   memset(out_file,0,sizeof(out_file));

   /* Get our command line arguments */
   opterr = 0;
   while ((i=getopt(argc,argv,"a:cd:f:hi:ln:p::st:vVx:"))!=EOF)
   {
      switch (i)
      {
         case 'a':  action='a'; strncpy(addr,optarg,sizeof(addr)-1);  break;
         case 'c':  if (action!='i') action='c'; create=1;            break;
         case 'd':  action='d'; strncpy(addr,optarg,sizeof(addr)-1);  break;
         case 'f':  action='f'; strncpy(addr,optarg,sizeof(addr)-1);  break;
         case 'i':  action='i'; strncpy(out_file,optarg,sizeof(out_file)-1);
                                                                      break;
         case 'h':  print_help();                                     break;
         case 'n':  strncpy(name,optarg,sizeof(name)-1);              break;
         case 'p':  action='p'; if (optarg!=NULL) rec_ttl=atoi(optarg); break;
         case 's':  action='s';                                       break;
         case 't':  rec_ttl=atoi(optarg);                             break;
         case 'v':  verbose=1;                                        break;
         case 'V':  print_ver();                                      break;
         case 'x':  action='x'; strncpy(out_file,optarg,sizeof(out_file)-1);
                                                                      break;
         case ':':  /* catch invalid options here */
         case '?':                                                    break;
         case 'l':  /* This is the default action */
         default:   action='l';                                       break;
      }
   }

   /* Get cache filename if specified */
   if (argc - optind == 0) print_help();   /* gots to have a filename!!     */
   in_file = argv[optind];

   /* Try to create our DB handle */
   if ( db_create(&dns_db, NULL, 0) )
   {
      fprintf(stderr,"Error: unable to create db handle!\n");
      exit(1);
   }

   /* force sane TTL value */
   if (rec_ttl > 99) rec_ttl=99;
   if (rec_ttl < 0 ) rec_ttl=7;

   /* Branch on 'action' specified   */
   switch (action)
   {
      case 'a': add_rec();                                            break;
      case 'c': create_cache();                                       break;
      case 'd': del_rec();                                            break;
      case 'f': find_rec();                                           break;
      case 'i': import_cache();                                       break;
      case 's': stat_cache();                                         break;
      case 'p': purge_cache();                                        break;
      case 'x': export_cache();                                       break;
      case 'l':
      default:  list_cache();                                         break;
   }
   exit(0);
}

/*********************************************/
/* LIST_CACHE - Dump out cache contents      */
/*********************************************/

void list_cache()
{
   int       i;
   char      ip_buf[48];
   u_int64_t t_rec=0;
   u_int64_t t_num=0;

   /* open the database (read-only) */
   if ((i=dns_db->open(dns_db, NULL, in_file, NULL, DB_HASH, DB_RDONLY, 0)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }

   /* Create a cursor */
   if ( dns_db->cursor(dns_db, NULL, &cursorp, 0) )
   {
      fprintf(stderr,"Error: Unable to create cursor!\n");
      exit(1);
   }

   /* get our runtime for TTL calculations */
   time(&runtime);

   if (verbose)
   {
      printf("Webalizer DNS Cache file listing generated %s\n",ctime(&runtime));
      printf("IP Address         TTL Age    Hostname\n");
      printf("--------------- ------------- ------------------------" \
             "-----------------------\n");
   }
      
   /* initalize data areas */
   memset(&q, 0, sizeof(DBT));
   memset(&r, 0, sizeof(DBT));
   memset(&dns_rec, 0, sizeof(struct dnsRec));

   /* Loop through database */
   while (!cursorp->c_get(cursorp, &q, &r, DB_NEXT))
   {
      /* got a record */
      t_rec++;
      memset(ip_buf, 0, sizeof(ip_buf));
      strncpy(ip_buf, q.data, (q.size>47)?47:q.size);  /* save IP address  */
      memcpy(&dns_rec, r.data, (r.size>DNSZ)?DNSZ:r.size);          

      if (dns_rec.numeric) t_num++;
      printf("%-15s [%s] %s\n",ip_buf,
             (dns_rec.timeStamp)?
                ttl_age(runtime, dns_rec.timeStamp):
                "-permanent-",
             dns_rec.hostName);

      /* done, clear for next rec */
      memset(&q, 0, sizeof(DBT));
      memset(&r, 0, sizeof(DBT));
   }

   if (verbose)
   {
      printf("------------------------------------------------------" \
             "-----------------------\n");
      printf("Filename: %s  (%llu records)\n",in_file, t_rec);
   }
}

/*********************************************/
/* PURGE_CACHE - Purge cache of expired recs */
/*********************************************/

void purge_cache()
{
   int       i;
   char      ip_buf[48];
   u_int64_t age=0;
   u_int64_t t_in=0;
   u_int64_t t_out=0;
   u_int64_t t_exp=0;

   /* file control struct */
   struct    flock our_flock;

   if (verbose) printf("Purging records over %d days from '%s'\n",
                        rec_ttl, in_file);

   /* open the input database (read-write) */
   if ((i=dns_db->open(dns_db, NULL, in_file, NULL, DB_HASH, 0, 0)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }

   /* get file descriptor */
   dns_db->fd(dns_db, &dns_fd);

   /* Try to lock the file */
   our_flock.l_whence=SEEK_SET;
   our_flock.l_start=0;
   our_flock.l_len=0;
   our_flock.l_type=F_WRLCK;

   if (fcntl(dns_fd,F_SETLK,&our_flock) <0)
   {
      /* Error - can't lock file */
      printf("Error: Unable to lock cache file: %s\n",strerror(errno));
      exit(1);
   }

   /* Create a cursor */
   if ( dns_db->cursor(dns_db, NULL, &cursorp, 0) )
   {
      fprintf(stderr,"Error: Unable to create cursor!\n");
      exit(1);
   }

   /* Try to create our output DB handle */
   if ( db_create(&out_db, NULL, 0) )
   {
      fprintf(stderr,"Error: unable to create output db handle!\n");
      exit(1);
   }

   /* generate output filename */
   memset(out_file, 0, sizeof(out_file));
   sprintf(out_file, "%s.new", in_file);

   /* open the output database (read-write) */
   if ((i=out_db->open(out_db, NULL, out_file, NULL,
                  DB_HASH, DB_CREATE|DB_EXCL, 0644)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",out_file,db_strerror(i));
      exit(1);
   }

   /* get our runtime for TTL calculations */
   time(&runtime);

   /* initalize data areas */
   memset(&q, 0, sizeof(DBT));
   memset(&r, 0, sizeof(DBT));

   /* Loop through database */
   while (!cursorp->c_get(cursorp, &q, &r, DB_NEXT))
   {
      /* got a record */
      t_in++;
      memcpy(&dns_rec, r.data, (r.size>DNSZ)?DNSZ:r.size);          

      /* get record ttl age */
      if (dns_rec.timeStamp==0) age=0;
      else age = runtime - dns_rec.timeStamp;

      if ( age <= (rec_ttl*86400) )
      {
         /* Good record.. insert into new cache file */
         if ( (i=out_db->put(out_db, NULL, &q, &r, 0)) != 0 )
         {
            fprintf(stderr,"Error: db_put fail: %s!\n",db_strerror(i));
            exit(1);
         }
         else t_out++;
      }
      else
      {
         /* Expired record */
         t_exp++;
         if (verbose)
         {
            memset(ip_buf, 0, sizeof(ip_buf));
            strncpy(ip_buf, q.data, (q.size>47)?47:q.size);
            printf("Purging %-16s [%s]\n",ip_buf,
               ttl_age(runtime,dns_rec.timeStamp));
         }
      }

      /* done, clear for next rec */
      memset(&q, 0, sizeof(DBT));
      memset(&r, 0, sizeof(DBT));
   }

   /* Successful exit! */
   our_flock.l_type=F_UNLCK;
   fcntl(dns_fd, F_SETLK, &our_flock);
   dns_db->close(dns_db, 0);
   out_db->close(out_db, 0);

   /* rename files */
   if (rename(out_file, in_file))
   {
      fprintf(stderr,"Error renaming file: %s\n",strerror(errno));
      exit(1);
   }
   
   if (verbose)
      printf("%llu of %llu records purged from '%s'\n",t_exp,t_in,in_file);
}

/*********************************************/
/* STAT_CACHE - Display cache stats/info     */
/*********************************************/

void stat_cache()
{
   /* Define some variables */
   int        i;
   time_t     min_age=0;                     /* min/max TTL age in cache   */
   time_t     max_age=0;
   u_int64_t  t_rec=0;                       /* Various record totals      */
   u_int64_t  t_err=0;
   u_int64_t  t_name=0;
   u_int64_t  t_num=0;
   u_int64_t  t_perm=0;
   u_int64_t  t_old=0;
   time_t     age;

   /* open the database (read-only) */
   if ((i=dns_db->open(dns_db, NULL, in_file, NULL, DB_HASH, DB_RDONLY, 0)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }

   /* Create a cursor */
   if ( dns_db->cursor(dns_db, NULL, &cursorp, 0) )
   {
      fprintf(stderr,"Error: Unable to create cursor!\n");
      exit(1);
   }

   /* get our runtime for TTL calculations */
   time(&runtime);

   /* initalize data areas */
   memset(&q, 0, sizeof(DBT));
   memset(&r, 0, sizeof(DBT));
   memset(&dns_rec, 0, sizeof(struct dnsRec));

   /* Loop through database */
   while (!cursorp->c_get(cursorp, &q, &r, DB_NEXT))
   {
      t_rec++;                                               /* add to total */
      if (r.size >= sizeof(dns_rec)) { t_err++; continue; }  /* size error?  */
      memcpy(&dns_rec, r.data, r.size);                      /* get record   */
      if (dns_rec.numeric) t_num++; else t_name++;           /* resolved?    */

      if (dns_rec.timeStamp!=0)                              /* permanent?   */
      {
         age=runtime-dns_rec.timeStamp;                      /* calc age     */
         if ((age < min_age) || (t_rec==1) ) min_age=age;    /* min/max age  */
         if ( age > max_age ) max_age=age;                   /* if not perm  */
         if ( age > (rec_ttl*86400)) t_old++;                /* purgable?    */
      }
      else t_perm++;                                         /* inc counter  */

      /* done, clear for next rec */
      memset(&q, 0, sizeof(DBT));
      memset(&r, 0, sizeof(DBT));
   }

   /* Print actual record counts */
   printf("Report generated on: %s",ctime(&runtime));
   printf("DNS Cache Filename : %s\n",in_file);

   printf("Total Records      : %llu\n",t_rec);
   printf("Total Resolved     : %llu\n",t_name);
   printf("Total Unresolved   : %llu\n",t_num);
   printf("Total Permanent    : %llu\n",t_perm);
   printf("Newest Record age  : %s\n",ttl_age(min_age,0));
   printf("Oldest Record age  : %s\n",ttl_age(max_age,0));
   printf("Total over %02d days : %llu\n",rec_ttl,t_old);
   if (t_err) printf("Record Size Errors : %llu\n",t_err);
   printf("\n");
}

/*********************************************/
/* FIND_REC - Find IP record in cache        */
/*********************************************/

void find_rec()
{
   int   i;
   char  ip_buf[48];

   /* open the database (read-only) */
   if ((i=dns_db->open(dns_db, NULL, in_file, NULL, DB_HASH, DB_RDONLY, 0)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }

   /* get our runtime for TTL calculations */
   time(&runtime);

   /* initalize data areas */
   memset(&q, 0, sizeof(DBT));
   memset(&r, 0, sizeof(DBT));
   memset(&dns_rec, 0, sizeof(struct dnsRec));

   /* search the cache */
   q.data = &addr;
   q.size = strlen(addr);
   if ( (i=dns_db->get(dns_db, NULL, &q, &r, 0)) == 0)
   {
      /* We found it! display info */
      memset(ip_buf, 0, sizeof(ip_buf));
      strncpy(ip_buf, q.data, (q.size>47)?47:q.size);  /* save IP address  */
      memcpy(&dns_rec, r.data, (r.size>DNSZ)?DNSZ:r.size);          

      if (verbose)
      {
         /* Verbose display */
         printf("Address  : %s\n",ip_buf);
         printf("Hostname : %s\n",dns_rec.hostName);
         printf("Resolved : %s\n",(dns_rec.numeric)?"No":"Yes");
         if (dns_rec.timeStamp)
         {
            /* Not Permanent */
            printf("Timestamp: %s",ctime(&dns_rec.timeStamp));
            printf("TTL age  : %s\n\n",ttl_age(runtime, dns_rec.timeStamp));
         }
         else
         {
            printf("Timestamp: N/A\n");
            printf("TTL age  : Permanent\n");
         }
      }
      else
      {
         /* Standard 1 line display */
         printf("%-15s [%s] %s\n",ip_buf,
             (dns_rec.timeStamp)?
                 ttl_age(runtime, dns_rec.timeStamp):
                 "-permanent-",
             dns_rec.hostName);
      }
   }
   else
   {
      if (i==DB_NOTFOUND)
         printf("%s not found!\n",addr);
      else
         printf("Error: %s\n",db_strerror(i));
   }
}

/*********************************************/
/* DEL_REC - Delete record from cache file   */
/*********************************************/

void del_rec()
{
   int   i;
   char  *cp;

   /* ensure we have addr string */
   if (addr[0]!='\0') cp=addr;
   else
   {
      fprintf(stderr,"Error: No IP address specified!\n");
      exit(1);
   }

   /* ensure IPv6 addresses are lowercase */
   cp=addr; while (*cp!='\0') *cp++=tolower(*cp);

   /* open the database (read-write) */
   if ((i=dns_db->open(dns_db, NULL, in_file, NULL, DB_HASH, 0, 0)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }

   /* initalize data areas */
   memset(&q, 0, sizeof(DBT));
   memset(&r, 0, sizeof(DBT));
   memset(&dns_rec, 0, sizeof(struct dnsRec));

   /* search the cache */
   q.data = &addr;
   q.size = strlen(addr);

   /* Try to delete the record */
   if ( (i=dns_db->del(dns_db, NULL, &q, 0)) )
   {
      if (i==DB_NOTFOUND)
      {
         printf("%s not found in cache!\n",addr);
         exit(1);
      }
      else
      {
         fprintf(stderr,"Error: %s\n",db_strerror(i));
         exit(1);
      }
   }
   dns_db->close(dns_db, 0);
   if (verbose)
      printf("%s sucessfully deleted from cache file\n",addr);
}

/*********************************************/
/* ADD_REC - Add record to cache file        */
/*********************************************/

void add_rec()
{
   int   i;
   char  *cp;

   /* ensure we have addr string */
   if (addr[0]!='\0') cp=addr;
   else
   {
      fprintf(stderr,"Error: No IP address specified!\n");
      exit(1);
   }

   /* and check size */
   if (strlen(addr)>47)
   {
      fprintf(stderr,"Error: IP address too long!\n");
      exit(1);
   }

   /* ensure everything is lowercase */
   cp=addr; while (*cp!='\0') *cp++=tolower(*cp);
   if (name[0]!='\0')
   {
      cp=name; while (*cp!='\0') *cp++=tolower(*cp);
   }

   /* open the database (read-write) */
   if ((i=dns_db->open(dns_db, NULL, in_file, NULL, DB_HASH, 0, 0)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }

   /* get our runtime for TTL calculations */
   time(&runtime);

   /* initalize data areas */
   memset(&q, 0, sizeof(DBT));
   memset(&r, 0, sizeof(DBT));
   memset(&dns_rec, 0, sizeof(struct dnsRec));

   /* search the cache */
   q.data = &addr;
   q.size = strlen(addr);
   if ( (i=dns_db->get(dns_db, NULL, &q, &r, 0)) == 0)
   {
      fprintf(stderr,"Error: %s already exists in cache!\n",addr);
      exit(1);
   }
   else
   {
      if (i!=DB_NOTFOUND)
      {
         fprintf(stderr,"Error: %s\n",db_strerror(i));
         exit(1);
      }
      else
      {
         /* check hostname */
         if (name[0]=='\0')
            strncpy(name,addr,strlen(addr));

         /* check if perm */
         if (rec_ttl==0) runtime=0;

         /* put it in the database */
         if (db_put(addr, name, (strcmp(name,addr))?0:1, runtime)==0)
            dns_db->close(dns_db,0);
         if (verbose)
            printf("%s sucessfully added to cache file\n",addr);
      }
   }
}

/*********************************************/
/* CREATE_CACHE - Create a new cache file    */
/*********************************************/

void create_cache()
{
   int   i;

   /* create the database */
   if ((i=dns_db->open(dns_db,NULL,in_file,NULL,
                  DB_HASH,DB_CREATE|DB_EXCL,0644)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }
   dns_db->close(dns_db,0);
   if (verbose) printf("Cache file %s created successfully\n",in_file);
}

/*********************************************/
/* IMPORT_CACHE - import cache from tab file */
/*********************************************/

void import_cache()
{
   int       i, flag=0;
   u_int64_t t_rec=0;
   FILE      *in_fp;
   char      ip_buf[48];
   char      buffer[4096];

   /* open the database (read-write) */
   if (create) flag=DB_CREATE|DB_EXCL;
   if ((i=dns_db->open(dns_db, NULL, in_file, NULL, DB_HASH, flag, 0644)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }

   /* open our import file */
   in_fp=fopen(out_file,"r");
   if (in_fp)
   {
      while ((fgets(buffer,4096,in_fp)) != NULL)
      {
         memset(&dns_rec, 0, sizeof(dns_rec));
         memset(&ip_buf, 0, sizeof(ip_buf));
         i = sscanf(buffer,"%47s\t%lu\t%d\t%" SMAXHOST "s",
                    ip_buf,
                    &dns_rec.timeStamp,
                    &dns_rec.numeric,
                    dns_rec.hostName);

         if (ip_buf[0]=='#') continue;  /* skip comments */

         if (i!=4)
         {
            fprintf(stderr,"Error reading tab file %s\n",out_file);
            exit(1);
         }

         t_rec++;   /* bump totals */

         /* put it in the database */
         if (db_put(ip_buf, dns_rec.hostName,
                    dns_rec.numeric, dns_rec.timeStamp)!=0)
         {
            fprintf(stderr,"Error inserting cache record:\n%s\n",buffer);
            exit(1);
         }
      }
   }
   else fprintf(stderr,"Error: File not found: %s\n",out_file);
   dns_db->close(dns_db,0);

   if (verbose) printf("%llu records imported into '%s' from file '%s'\n",
                       t_rec, in_file, out_file);
}

/*********************************************/
/* EXPORT_CACHE - export cache to tab file   */
/*********************************************/

void export_cache()
{
   int       i;
   u_int64_t t_rec=0;
   char      ip_buf[48];
   FILE      *out_fp;
   struct    stat out_stat;

   /* make sure files are different! */
   if (!strcmp(in_file,out_file))
   {
      fprintf(stderr,"Error: Bad export filename: %s\n",out_file);
      exit(1);
   }

   /* open the database (read-only) */
   if ((i=dns_db->open(dns_db, NULL, in_file, NULL, DB_HASH, DB_RDONLY, 0)))
   {
      /* Error opening the cache file.. tell user and exit */
      fprintf(stderr,"Error: %s: %s\n",in_file,db_strerror(i));
      exit(1);
   }

   /* Create a cursor */
   if ( dns_db->cursor(dns_db, NULL, &cursorp, 0) )
   {
      fprintf(stderr,"Error: Unable to create cursor!\n");
      exit(1);
   }

   /* stat output file */
   if ( !(lstat(out_file, &out_stat)) )
   {
      /* check if the file is a symlink */
      if ( S_ISLNK(out_stat.st_mode) )
      {
         fprintf(stderr,"%s %s\n","Error: File is a symlink:",out_file);
         exit(1);
      }
   }

   /* open output file */
   if ( (out_fp=fopen(out_file,"w")) == NULL)
   {
      fprintf(stderr,"%s %s\n","Error: Cannot create file:",out_file);
      exit(1);
   }

   /* initalize data areas */
   memset(&q, 0, sizeof(DBT));
   memset(&r, 0, sizeof(DBT));
   memset(&dns_rec, 0, sizeof(struct dnsRec));

   /* Loop through database */
   while (!cursorp->c_get(cursorp, &q, &r, DB_NEXT))
   {
      /* got a record */
      t_rec++;
      memset(ip_buf, 0, sizeof(ip_buf));
      strncpy(ip_buf, q.data, (q.size>47)?47:q.size);  /* save IP address  */
      memcpy(&dns_rec, r.data, (r.size>DNSZ)?DNSZ:r.size);          

      /* Print out tab delimited line          */
      /* Format: IP timestamp numeric hostname */
      fprintf(out_fp,"%s\t%lu\t%d\t%s\n",
              ip_buf,dns_rec.timeStamp,
              dns_rec.numeric,
              dns_rec.hostName);

      /* done, clear for next rec */
      memset(&q, 0, sizeof(DBT));
      memset(&r, 0, sizeof(DBT));
   }
   dns_db->close(dns_db,0);
   fclose(out_fp);

   if (verbose) printf("%llu records exported from '%s' to file '%s'\n",
                       t_rec, in_file, out_file);
}

/*********************************************/
/* DB_PUT - put key/val in the cache db      */
/*********************************************/

static int db_put(char *key, char *value, int numeric, time_t ttl)
{

   /* dnsRecord structure used in database */
   struct dnsRecord
   {
          time_t    timeStamp;             /* Timestamp of resolv data    */
          int       numeric;               /* 0: Name, 1: IP-address      */
          char      hostName[1];           /* Hostname buffer (variable)  */
   };

   int    i;
   DBT    k, v;
   struct dnsRecord *recPtr = NULL;
   int    nameLen = strlen(value)+1;

   /* Align to multiple of eight bytes */
   int recSize = (sizeof(struct dnsRecord)+nameLen+7) & ~0x7;

   /* make sure we have a db ;) */
   if(dns_db)
   {
      if((recPtr = calloc(1, recSize)))
      {
         recPtr->timeStamp = ttl;
         recPtr->numeric = numeric;
         memcpy(&recPtr->hostName, value, nameLen);
         memset(&k, 0, sizeof(k));
         memset(&v, 0, sizeof(v));

         k.data = key;
         k.size = strlen(key);

         v.size = recSize;
         v.data = recPtr;

         if ( (i=dns_db->put(dns_db, NULL, &k, &v, 0)) != 0 )
            fprintf(stderr,"Error: db_put fail: %s!\n",db_strerror(i));
         free(recPtr);
      }
      else return 1;
   }
   else return 1;
   return i;
}
#endif /* USE_DNS */
