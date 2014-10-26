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

/* Fix broken Zlib 64 bitness */
#if _FILE_OFFSET_BITS == 64
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>                           /* normal stuff             */
#include <locale.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <zlib.h>
#include <sys/stat.h>

/* ensure getopt */
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

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

#ifdef USE_DNS
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <db.h>
#endif  /* USE_DNS */

#ifdef USE_GEOIP
#include <GeoIP.h>
#endif

#ifdef USE_BZIP
#include <bzlib.h>
int bz2_rewind(void **, char *, char *);
#endif

#include "webalizer.h"                         /* main header              */
#include "output.h"
#include "parser.h"
#include "preserve.h"
#include "hashtab.h"
#include "linklist.h"
#include "webalizer_lang.h"                    /* lang. support            */
#ifdef USE_DNS
#include "dns_resolv.h"
#endif

/* internal function prototypes */

void    clear_month();                              /* clear monthly stuff */
char    *unescape(char *);                          /* unescape URLs       */
void    print_opts(char *);                         /* print options       */
void    print_version();                            /* duhh...             */
int     isurlchar(unsigned char, int);              /* valid URL char fnc. */
void    get_config(char *);                         /* Read a config file  */
static  char *save_opt(char *);                     /* save conf option    */
void    srch_string(char *);                        /* srch str analysis   */
char	*get_domain(char *);                        /* return domain name  */
void    agent_mangle(char *);                       /* reformat user agent */
char    *our_gzgets(void *, char *, int);           /* our gzgets          */
int     ouricmp(char *, char *);                    /* case ins. compare   */
int     isipaddr(char *);                           /* is IP address test  */

/*********************************************/
/* GLOBAL VARIABLES                          */
/*********************************************/

char    *version     = "2.23";                /* program version          */
char    *editlvl     = "08";                  /* edit level               */
char    *moddate     = "26-Aug-2013";         /* modification date        */
char    *copyright   = "Copyright 1997-2013 by Bradford L. Barrett";

int     verbose      = 2;                     /* 2=verbose,1=err, 0=none  */ 
int     debug_mode   = 0;                     /* debug mode flag          */
int     time_me      = 0;                     /* timing display flag      */
int     local_time   = 1;                     /* 1=localtime 0=GMT (UTC)  */
int     hist_gap     = 0;                     /* 1=error w/hist, save bkp */
int     ignore_hist  = 0;                     /* history flag (1=skip)    */
int     ignore_state = 0;                     /* state flag (1=skip)      */
int     default_index= 1;                     /* default index. (1=yes)   */
int     hourly_graph = 1;                     /* hourly graph display     */
int     hourly_stats = 1;                     /* hourly stats table       */
int     daily_graph  = 1;                     /* daily graph display      */
int     daily_stats  = 1;                     /* daily stats table        */
int     ctry_graph   = 1;                     /* country graph display    */
int     shade_groups = 1;                     /* Group shading 0=no 1=yes */
int     hlite_groups = 1;                     /* Group hlite 0=no 1=yes   */
int     mangle_agent = 0;                     /* mangle user agents       */
int     incremental  = 0;                     /* incremental mode 1=yes   */
int     use_https    = 0;                     /* use 'https://' on URLs   */
int     htaccess     = 0;                     /* create .htaccess? (0=no) */
int     stripcgi     = 1;                     /* strip url cgi (0=no)     */
int     normalize    = 1;                     /* normalize CLF URL (0=no) */
int     trimsquid    = 0;                     /* trim squid urls (0=no)   */
int     searchcasei  = 1;                     /* case insensitive search  */
int     visit_timeout= 1800;                  /* visit timeout (seconds)  */
int     graph_legend = 1;                     /* graph legend (1=yes)     */
int     graph_lines  = 2;                     /* graph lines (0=none)     */
int     fold_seq_err = 0;                     /* fold seq err (0=no)      */
int     log_type     = LOG_CLF;               /* log type (default=CLF)   */
int     group_domains= 0;                     /* Group domains 0=none     */
int     hide_sites   = 0;                     /* Hide ind. sites (0=no)   */
int     link_referrer= 0;                     /* Link referrers (0=no)    */
char    *hname       = NULL;                  /* hostname for reports     */
char    *state_fname = "webalizer.current";   /* run state file name      */
char    *hist_fname  = "webalizer.hist";      /* name of history file     */
char    *html_ext    = "html";                /* HTML file suffix         */
char    *dump_ext    = "tab";                 /* Dump file suffix         */
char    *conf_fname  = NULL;                  /* name of config file      */
char    *log_fname   = NULL;                  /* log file pointer         */
char    *out_dir     = NULL;                  /* output directory         */
char    *blank_str   = "";                    /* blank string             */
char    *geodb_fname = NULL;                  /* GeoDB database filename  */
char    *dns_cache   = NULL;                  /* DNS cache file name      */
int     dns_children = 0;                     /* DNS children (0=don't do)*/
int     cache_ips    = 0;                     /* CacheIPs in DB (0=no)    */
int     cache_ttl    = 7;                     /* DNS Cache TTL (days)     */
int     geodb        = 0;                     /* Use GeoDB (0=no)         */
int     graph_mths   = 12;                    /* # months in index graph  */
int     index_mths   = 12;                    /* # months in index table  */
int     year_hdrs    = 1;                     /* index year seperators    */
int     year_totals  = 1;                     /* index year subtotals     */
int     use_flags    = 0;                     /* Show flags in ctry table */
char    *flag_dir    = "flags";               /* location of flag icons   */

#ifdef USE_GEOIP
int     geoip        = 0;                     /* Use GeoIP (0=no)         */
char    *geoip_db    = NULL;                  /* GeoIP database filename  */
GeoIP   *geo_fp      = NULL;                  /* GeoIP database handle    */
#endif

int     ntop_sites   = 30;                    /* top n sites to display   */
int     ntop_sitesK  = 10;                    /* top n sites (by kbytes)  */
int     ntop_urls    = 30;                    /* top n url's to display   */
int     ntop_urlsK   = 10;                    /* top n url's (by kbytes)  */
int     ntop_entry   = 10;                    /* top n entry url's        */
int     ntop_exit    = 10;                    /* top n exit url's         */
int     ntop_refs    = 30;                    /* top n referrers ""       */
int     ntop_agents  = 15;                    /* top n user agents ""     */
int     ntop_ctrys   = 30;                    /* top n countries   ""     */
int     ntop_search  = 20;                    /* top n search strings     */
int     ntop_users   = 20;                    /* top n users to display   */

int     all_sites    = 0;                     /* List All sites (0=no)    */
int     all_urls     = 0;                     /* List All URLs  (0=no)    */
int     all_refs     = 0;                     /* List All Referrers       */
int     all_agents   = 0;                     /* List All User Agents     */
int     all_search   = 0;                     /* List All Search Strings  */
int     all_users    = 0;                     /* List All Usernames       */

int     dump_sites   = 0;                     /* Dump tab delimited sites */
int     dump_urls    = 0;                     /* URLs                     */
int     dump_refs    = 0;                     /* Referrers                */
int     dump_agents  = 0;                     /* User Agents              */
int     dump_users   = 0;                     /* Usernames                */
int     dump_search  = 0;                     /* Search strings           */
int     dump_header  = 0;                     /* Dump header as first rec */
char    *dump_path   = NULL;                  /* Path for dump files      */

int        cur_year=0, cur_month=0,           /* year/month/day/hour      */
           cur_day=0, cur_hour=0,             /* tracking variables       */
           cur_min=0, cur_sec=0;

u_int64_t  cur_tstamp=0;                      /* Timestamp...             */
u_int64_t  rec_tstamp=0;  
u_int64_t  req_tstamp=0;
u_int64_t  epoch;                             /* used for timestamp adj.  */

int        check_dup=0;                       /* check for dup flag       */
int        gz_log=COMP_NONE;                  /* gziped log? (0=no)       */

double     t_xfer=0.0;                        /* monthly total xfer value */
u_int64_t  t_hit=0,t_file=0,t_site=0,         /* monthly total vars       */
           t_url=0,t_ref=0,t_agent=0,
           t_page=0, t_visit=0, t_user=0;

double     tm_xfer[31];                       /* daily transfer totals    */

u_int64_t  tm_hit[31], tm_file[31],           /* daily total arrays       */
           tm_site[31], tm_page[31],
           tm_visit[31];

u_int64_t  dt_site;                           /* daily 'sites' total      */

u_int64_t  ht_hit=0, mh_hit=0;                /* hourly hits totals       */

u_int64_t  th_hit[24], th_file[24],           /* hourly total arrays      */
           th_page[24];

double     th_xfer[24];

int        f_day,l_day;                       /* first/last day vars      */

struct     utsname system_info;               /* system info structure    */

u_int64_t  ul_bogus =0;                       /* Dummy counter for groups */

struct     log_struct log_rec;                /* expanded log storage     */

void       *zlog_fp;                          /* compressed logfile ptr   */
FILE       *log_fp;                           /* regular logfile pointer  */

char       buffer[BUFSIZE];                   /* log file record buffer   */
char       tmp_buf[BUFSIZE];                  /* used to temp save above  */

CLISTPTR   *top_ctrys    = NULL;              /* Top countries table      */

#define    GZ_BUFSIZE 16384                   /* our_getfs buffer size    */
char       f_buf[GZ_BUFSIZE];                 /* our_getfs buffer         */
char       *f_cp=f_buf+GZ_BUFSIZE;            /* pointer into the buffer  */
int        f_end=0;                           /* count to end of buffer   */ 

char    hit_color[]   = "#00805c";            /* graph hit color          */
char    file_color[]  = "#0040ff";            /* graph file color         */
char    site_color[]  = "#ff8000";            /* graph site color         */
char    kbyte_color[] = "#ff0000";            /* graph kbyte color        */
char    page_color[]  = "#00e0ff";            /* graph page color         */
char    visit_color[] = "#ffff00";            /* graph visit color        */
char    misc_color[]  = "#00e0ff";            /* graph misc color         */
char    pie_color1[]  = "#800080";            /* pie additionnal color 1  */
char    pie_color2[]  = "#80ffc0";            /* pie additionnal color 2  */
char    pie_color3[]  = "#ff00ff";            /* pie additionnal color 3  */
char    pie_color4[]  = "#ffc080";            /* pie additionnal color 4  */

/*********************************************/
/* MAIN - start here                         */
/*********************************************/

int main(int argc, char *argv[])
{
   int      i;                           /* generic counter             */
   char     *cp1, *cp2, *cp3;            /* generic char pointers       */
   char     host_buf[MAXHOST+1];         /* used to save hostname       */

   NLISTPTR lptr;                        /* generic list pointer        */

   extern char *optarg;                  /* used for command line       */
   extern int optind;                    /* parsing routine 'getopt'    */
   extern int opterr;

   time_t start_time, end_time;          /* program timers              */
   float  temp_time;                     /* temporary time storage      */

   int    rec_year,rec_month=1,rec_day,rec_hour,rec_min,rec_sec;

   int       good_rec    =0;             /* 1 if we had a good record   */
   u_int64_t total_rec   =0;             /* Total Records Processed     */
   u_int64_t total_ignore=0;             /* Total Records Ignored       */
   u_int64_t total_bad   =0;             /* Total Bad Records           */

   int    max_ctry;                      /* max countries defined       */

   /* month names used for parsing logfile (shouldn't be lang specific) */
   char *log_month[12]={ "jan", "feb", "mar",
                         "apr", "may", "jun",
                         "jul", "aug", "sep",
                         "oct", "nov", "dec"};

   /* stat struct for files */
   struct stat log_stat;

   /* Assume that LC_CTYPE is what the user wants for non-ASCII chars   */
   setlocale(LC_CTYPE,"");

   /* initalize epoch */
   epoch=jdate(1,1,1970);                /* used for timestamp adj.     */

   sprintf(tmp_buf,"%s/webalizer.conf",ETCDIR);
   /* check for default config file */
   if (!access("webalizer.conf",F_OK))
      get_config("webalizer.conf");
   else if (!access(tmp_buf,F_OK))
      get_config(tmp_buf);

   /* get command line options */
   opterr = 0;     /* disable parser errors */
   while ((i=getopt(argc,argv,"a:A:bc:C:dD:e:E:fF:g:GhHiI:jJ:k:K:l:Lm:M:n:N:o:O:pP:qQr:R:s:S:t:Tu:U:vVwW:x:XYz:Z"))!=EOF)
   {
      switch (i)
      {
        case 'a': add_nlist(optarg,&hidden_agents); break; /* Hide agents   */
        case 'A': ntop_agents=atoi(optarg);  break;  /* Top agents          */
        case 'b': ignore_state=1;            break;  /* Ignore state file   */
        case 'c': get_config(optarg);        break;  /* Config file         */
        case 'C': ntop_ctrys=atoi(optarg);   break;  /* Top countries       */
        case 'd': debug_mode=1;              break;  /* Debug               */
	case 'D': dns_cache=optarg;          break;  /* DNS Cache filename  */
        case 'e': ntop_entry=atoi(optarg);   break;  /* Top entry pages     */
        case 'E': ntop_exit=atoi(optarg);    break;  /* Top exit pages      */
        case 'f': fold_seq_err=1;            break;  /* Fold sequence errs  */
        case 'F': log_type=(tolower(optarg[0])=='f')?
                   LOG_FTP:(tolower(optarg[0])=='s')?
                   LOG_SQUID:(tolower(optarg[0])=='w')?
                   LOG_W3C:LOG_CLF;          break;  /* define log type     */
	case 'g': group_domains=atoi(optarg); break; /* GroupDomains (0=no) */
        case 'G': hourly_graph=0;            break;  /* no hourly graph     */
        case 'h': print_opts(argv[0]);       break;  /* help                */
        case 'H': hourly_stats=0;            break;  /* no hourly stats     */
        case 'i': ignore_hist=1;             break;  /* Ignore history      */
        case 'I': add_nlist(optarg,&index_alias); break; /* Index alias     */
        case 'j': geodb=1;                   break;  /* Enable GeoDB        */
        case 'J': geodb_fname=optarg;        break;  /* GeoDB db filename   */
        case 'k': graph_mths=atoi(optarg);   break;  /* # months idx graph  */
        case 'K': index_mths=atoi(optarg);   break;  /* # months idx table  */
        case 'l': graph_lines=atoi(optarg);  break;  /* Graph Lines         */
        case 'L': graph_legend=0;            break;  /* Graph Legends       */
        case 'm': visit_timeout=atoi(optarg); break; /* Visit Timeout       */
        case 'M': mangle_agent=atoi(optarg); break;  /* mangle user agents  */
        case 'n': hname=optarg;              break;  /* Hostname            */
        case 'N': dns_children=atoi(optarg); break;  /* # of DNS children   */
        case 'o': out_dir=optarg;            break;  /* Output directory    */
        case 'O': add_nlist(optarg,&omit_page); break; /* pages not counted */
        case 'p': incremental=1;             break;  /* Incremental run     */
        case 'P': add_nlist(optarg,&page_type); break; /* page view types   */
        case 'q': verbose=1;                 break;  /* Quiet (verbose=1)   */
        case 'Q': verbose=0;                 break;  /* Really Quiet        */
        case 'r': add_nlist(optarg,&hidden_refs);   break; /* Hide referrer */
        case 'R': ntop_refs=atoi(optarg);    break;  /* Top referrers       */
        case 's': add_nlist(optarg,&hidden_sites);  break; /* Hide site     */
        case 'S': ntop_sites=atoi(optarg);   break;  /* Top sites           */
        case 't': msg_title=optarg;          break;  /* Report title        */
        case 'T': time_me=1;                 break;  /* TimeMe              */
        case 'u': add_nlist(optarg,&hidden_urls);   break; /* hide URL      */
        case 'U': ntop_urls=atoi(optarg);    break;  /* Top urls            */
        case 'v': verbose=2; debug_mode=1;   break;  /* Verbose             */
        case 'V': print_version();           break;  /* Version             */
#ifdef USE_GEOIP
        case 'w': geoip=1;                   break;  /* Enable GeoIP        */
        case 'W': geoip_db=optarg;           break;  /* GeoIP database name */
#endif
        case 'x': html_ext=optarg;           break;  /* HTML file extension */
        case 'X': hide_sites=1;              break;  /* Hide ind. sites     */
        case 'Y': ctry_graph=0;              break;  /* Supress ctry graph  */
        case 'Z': normalize=0;               break;  /* Dont normalize URLs */
        case 'z': use_flags=1; flag_dir=optarg; break; /* Ctry flag dir     */
      }
   }

   if (argc - optind != 0) log_fname = argv[optind];
   if ( log_fname && (log_fname[0]=='-')) log_fname=NULL; /* force STDIN?   */

   /* check for gzipped file - .gz */
   if (log_fname) if (!strcmp((log_fname+strlen(log_fname)-3),".gz"))
      gz_log=COMP_GZIP;

#ifdef USE_BZIP
   /* check for bzip file - .bz2 */
   if (log_fname) if (!strcmp((log_fname+strlen(log_fname)-4),".bz2"))
      gz_log=COMP_BZIP;
#endif

   /* setup our internal variables */
   init_counters();                      /* initalize (zero) main counters  */
   memset(hist, 0, sizeof(hist));        /* initalize (zero) history array  */

   /* add default index. alias if needed */
   if (default_index) add_nlist("index.",&index_alias);

   if (page_type==NULL)                  /* check if page types present     */
   {
      if ((log_type==LOG_CLF)||(log_type==LOG_SQUID)||(log_type==LOG_W3C))
      {
         add_nlist("htm*"  ,&page_type); /* if no page types specified, we  */
         add_nlist("cgi"   ,&page_type); /* use the default ones here...    */
         if (!isinlist(page_type,html_ext)) add_nlist(html_ext,&page_type);
      }
      else add_nlist("txt" ,&page_type); /* FTP logs default to .txt        */
   }

   for (max_ctry=0;ctry[max_ctry].desc;max_ctry++);
   if (ntop_ctrys > max_ctry) ntop_ctrys = max_ctry;   /* force upper limit */
   if (graph_lines> 20)       graph_lines= 20;         /* keep graphs sane! */
   if (graph_mths<12)         graph_mths=12;
   if (graph_mths>GRAPHMAX)   graph_mths=GRAPHMAX;
   if (index_mths<12)         index_mths=12;
   if (index_mths>HISTSIZE)   index_mths=HISTSIZE;

   if (log_type == LOG_FTP)
   {
      /* disable stuff for ftp logs */
      ntop_entry=ntop_exit=0;
      ntop_search=0;
   }
   else
   {
      if (search_list==NULL)
      {
         /* If no search engines defined, define some :) */
         add_glist(".google.       q="      ,&search_list);
         add_glist("yahoo.com      p="      ,&search_list);
         add_glist("altavista.com  q="      ,&search_list);
         add_glist("aolsearch.     query="  ,&search_list);
         add_glist("ask.co         q="      ,&search_list);
         add_glist("eureka.com     q="      ,&search_list);
         add_glist("lycos.com      query="  ,&search_list);
         add_glist("hotbot.com     MT="     ,&search_list);
         add_glist("msn.com        q="      ,&search_list);
         add_glist("infoseek.com   qt="     ,&search_list);
         add_glist("webcrawler searchText=" ,&search_list);
         add_glist("excite         search=" ,&search_list);
         add_glist("netscape.com   query="  ,&search_list);
         add_glist("mamma.com      query="  ,&search_list);
         add_glist("alltheweb.com  q="      ,&search_list);
         add_glist("northernlight.com qr="  ,&search_list);
      }
   }

   /* ensure entry/exits don't exceed urls */
   i=(ntop_urls>ntop_urlsK)?ntop_urls:ntop_urlsK;
   if (ntop_entry>i) ntop_entry=i;
   if (ntop_exit>i)  ntop_exit=i;

   for (i=0;i<MAXHASH;i++)
   {
      sm_htab[i]=sd_htab[i]=NULL;        /* initalize hash tables           */
      um_htab[i]=NULL;
      rm_htab[i]=NULL;
      am_htab[i]=NULL;
      sr_htab[i]=NULL;
   }

   /* Be polite and announce yourself... */
   if (verbose>1)
   {
      uname(&system_info);
      printf("Webalizer V%s-%s (%s %s %s) %s\n", version,editlvl,
              system_info.sysname, system_info.release,
              system_info.machine,language);
   }

#ifndef USE_DNS
   if (strstr(argv[0],"webazolver")!=0)
      /* DNS support not present, aborting... */
      { printf("%s\n",msg_dns_abrt); exit(1); }
#else
   /* Force sane values for cache TTL */
   if (cache_ttl<1)   cache_ttl=1;
   if (cache_ttl>100) cache_ttl=100;
#endif  /* USE_DNS */

   /* open log file */
   if (log_fname)
   {
      /* stat the file */
      if ( !(lstat(log_fname, &log_stat)) )
      {
         /* check if the file a symlink */
         if ( S_ISLNK(log_stat.st_mode) )
         {
            if (verbose)
            fprintf(stderr,"%s %s (symlink)\n",msg_log_err,log_fname);
            exit(EBADF);
         }
      }

      if (gz_log)
      {
         /* open compressed file */
#ifdef USE_BZIP
         if (gz_log==COMP_BZIP)
            zlog_fp = BZ2_bzopen(log_fname,"rb");
         else
#endif
         zlog_fp = gzopen(log_fname, "rb");
         if (zlog_fp==Z_NULL)
         {
            /* Error: Can't open log file ... */
            fprintf(stderr, "%s %s (%d)\n",msg_log_err,log_fname,ENOENT);
            exit(ENOENT);
         }
      }
      else
      {
         /* open regular file */
         log_fp = fopen(log_fname,"r");
         if (log_fp==NULL)
         {
            /* Error: Can't open log file ... */
            fprintf(stderr, "%s %s\n",msg_log_err,log_fname);
            exit(1);
         }
      }
   }

   /* Using logfile ... */
   if (verbose>1)
   {
      printf("%s %s (",msg_log_use,log_fname?log_fname:"STDIN");
      if (gz_log==COMP_GZIP) printf("gzip-");
#ifdef USE_BZIP
      if (gz_log==COMP_BZIP) printf("bzip-");
#endif
      switch (log_type)
      {
         /* display log file type hint */
         case LOG_CLF:   printf("clf)\n");   break;
         case LOG_FTP:   printf("ftp)\n");   break;
         case LOG_SQUID: printf("squid)\n"); break;
         case LOG_W3C:   printf("w3c)\n");   break;
      }
   }

   /* switch directories if needed */
   if (out_dir)
   {
      if (chdir(out_dir) != 0)
      {
         /* Error: Can't change directory to ... */
         fprintf(stderr, "%s %s\n",msg_dir_err,out_dir);
         exit(1);
      }
   }

#ifdef USE_DNS
   if (strstr(argv[0],"webazolver")!=0)
   {
      if (!dns_children) dns_children=5;  /* default dns children if needed */
      if (!dns_cache)
      {
         /* No cache file specified, aborting... */
         fprintf(stderr,"%s\n",msg_dns_nocf);     /* Must have a cache file */
         exit(1);
      }
   }

   if (dns_cache && dns_children)    /* run-time resolution */
   {
      if (dns_children > MAXCHILD) dns_children=MAXCHILD;
      /* DNS Lookup (#children): */
      if (verbose>1) printf("%s (%d): ",msg_dns_rslv,dns_children);
      fflush(stdout);
      (gz_log)?dns_resolver(zlog_fp):dns_resolver(log_fp);
#ifdef USE_BZIP
      (gz_log==COMP_BZIP)?bz2_rewind(&zlog_fp, log_fname, "rb"):
#endif
      (gz_log==COMP_GZIP)?gzrewind(zlog_fp):
      (log_fname)?rewind(log_fp):exit(0);
   }

   if (strstr(argv[0],"webazolver")!=0) exit(0);   /* webazolver exits here */

   if (dns_cache)
   {
      if (!open_cache()) { dns_cache=NULL; dns_db=NULL; }
      else
      {
         /* Using DNS cache file <filaneme> */
         if (verbose>1) printf("%s %s\n",msg_dns_usec,dns_cache);
      }
   }

   /* Open GeoDB? */
   if (geodb)
   {
      geo_db=geodb_open(geodb_fname);
      if (geo_db==NULL)
      {
         if (verbose) printf("%s: %s\n",msg_geo_open,
            (geodb_fname)?geodb_fname:msg_geo_dflt);
         if (verbose) printf("GeoDB %s\n",msg_geo_nolu);
         geodb=0;
      }
      else if (verbose>1) printf("%s %s\n",
         msg_geo_use,geodb_ver(geo_db,buffer));
#ifdef USE_GEOIP
      if (geoip) geoip=0;   /* Disable GeoIP if using GeoDB */
#endif
   }
#endif  /* USE_DNS */

#ifdef USE_GEOIP
   /* open GeoIP database */
   if (geoip)
   {
      if (geoip_db!=NULL)
         geo_fp=GeoIP_open(geoip_db, GEOIP_MEMORY_CACHE);
      else
         geo_fp=GeoIP_new(GEOIP_MEMORY_CACHE);

      /* Did we open one? */
      if (geo_fp==NULL)
      {
         /* couldn't open.. warn user */
         if (verbose) printf("GeoIP %s\n",msg_geo_nolu);
         geoip=0;
      }
      else if (verbose>1) printf("%s %s (%s)\n",msg_geo_use,
         GeoIPDBDescription[(int)geo_fp->databaseType],
         (geoip_db==NULL)?msg_geo_dflt:geo_fp->file_path);
   }
#endif /* USE_GEOIP */

   /* Creating output in ... */
   if (verbose>1)
      printf("%s %s\n",msg_dir_use,out_dir?out_dir:msg_cur_dir);

   /* prep hostname */
   if (!hname)
   {
      if (uname(&system_info)) hname="localhost";
      else hname=system_info.nodename;
   }

   /* Hostname for reports is ... */
   if (strlen(hname)) if (verbose>1) printf("%s '%s'\n",msg_hostname,hname);

   /* get past history */
   if (ignore_hist) { if (verbose>1) printf("%s\n",msg_ign_hist); }
   else get_history();

   if (incremental)                      /* incremental processing?         */
   {
      if ((i=restore_state()))           /* restore internal data structs   */
      {
         /* Error: Unable to restore run data (error num) */
         /* if (verbose) fprintf(stderr,"%s (%d)\n",msg_bad_data,i); */
         fprintf(stderr,"%s (%d)\n",msg_bad_data,i);
         exit(1);
      }
   }

   /* Allocate memory for our TOP countries array */
   if (ntop_ctrys  != 0)
   { if ( (top_ctrys=calloc(ntop_ctrys,sizeof(CLISTPTR))) == NULL)
    /* Can't get memory, Top Countries disabled! */
    {if (verbose) fprintf(stderr,"%s\n",msg_nomem_tc); ntop_ctrys=0;}}

   /* get processing start time */
   start_time = time(NULL);

   /*********************************************/
   /* MAIN PROCESS LOOP - read through log file */
   /*********************************************/

   while ( (gz_log)?(our_gzgets(zlog_fp,buffer,BUFSIZE) != Z_NULL):
           (fgets(buffer,BUFSIZE,log_fname?log_fp:stdin) != NULL))
   {
      total_rec++;
      if (strlen(buffer) == (BUFSIZE-1))
      {
         if (verbose)
         {
            fprintf(stderr,"%s",msg_big_rec);
            if (debug_mode) fprintf(stderr,":\n%s",buffer);
            else fprintf(stderr,"\n");
         }

         total_bad++;                     /* bump bad record counter      */

         /* get the rest of the record */
         while ( (gz_log)?(our_gzgets(zlog_fp,buffer,BUFSIZE)!=Z_NULL):
                 (fgets(buffer,BUFSIZE,log_fname?log_fp:stdin)!=NULL))
         {
            if (strlen(buffer) < BUFSIZE-1)
            {
               if (debug_mode && verbose) fprintf(stderr,"%s\n",buffer);
               break;
            }
            if (debug_mode && verbose) fprintf(stderr,"%s",buffer);
         }
         continue;                        /* go get next record if any    */
      }

      /* got a record... */
      strcpy(tmp_buf, buffer);            /* save buffer in case of error */
      if (parse_record(buffer))           /* parse the record             */
      {
         /*********************************************/
         /* PASSED MINIMAL CHECKS, DO A LITTLE MORE   */
         /*********************************************/

         /* convert month name to lowercase */
         for (i=4;i<7;i++)
            log_rec.datetime[i]=tolower(log_rec.datetime[i]);

         /* lowercase sitename/IPv6 addresses */
         cp1=log_rec.hostname;
         while (*cp1++!='\0') *cp1=tolower(*cp1);

         /* get year/month/day/hour/min/sec values    */
         for (i=0;i<12;i++)
         {
            if (strncmp(log_month[i],&log_rec.datetime[4],3)==0)
               { rec_month = i+1; break; }
         }

         rec_year=atoi(&log_rec.datetime[8]);    /* get year number (int)   */
         rec_day =atoi(&log_rec.datetime[1]);    /* get day number          */
         rec_hour=atoi(&log_rec.datetime[13]);   /* get hour number         */
         rec_min =atoi(&log_rec.datetime[16]);   /* get minute number       */
         rec_sec =atoi(&log_rec.datetime[19]);   /* get second number       */

         /* Kludge for Netscape server time (0-24?) error                   */
         if (rec_hour>23) rec_hour=0;

         /* minimal sanity check on date */
         if ((i>=12)||(rec_min>59)||(rec_sec>60)||(rec_year<1990))
         {
            total_bad++;                /* if a bad date, bump counter      */
            if (verbose)
            {
               fprintf(stderr,"%s: %s [%llu]",
                 msg_bad_date,log_rec.datetime,total_rec);
               if (debug_mode) fprintf(stderr,":\n%s\n",tmp_buf);
               else fprintf(stderr,"\n");
            }
            continue;                   /* and ignore this record           */
         }

         /*********************************************/
         /* GOOD RECORD, CHECK INCREMENTAL/TIMESTAMPS */
         /*********************************************/

         /* Flag as a good one */
         good_rec = 1;

         /* get current records timestamp (seconds since epoch) */
         req_tstamp=cur_tstamp;
         rec_tstamp=((jdate(rec_day,rec_month,rec_year)-epoch)*86400)+
                     (rec_hour*3600)+(rec_min*60)+rec_sec;

         /* Do we need to check for duplicate records? (incremental mode)   */
         if (check_dup)
         {
            /* check if less than/equal to last record processed            */
            if ( rec_tstamp <= cur_tstamp )
            {
               /* if it is, assume we have already processed and ignore it  */
               total_ignore++;
               continue;
            }
            else
            {
               /* if it isn't.. disable any more checks this run            */
               check_dup=0;
               /* now check if it's a new month                             */
               if ( (cur_month != rec_month) || (cur_year != rec_year) )
               {
                  clear_month();
                  cur_sec   = rec_sec;          /* set current counters     */
                  cur_min   = rec_min;
                  cur_hour  = rec_hour;
                  cur_day   = rec_day;
                  cur_month = rec_month;
                  cur_year  = rec_year;
                  cur_tstamp= rec_tstamp;
                  f_day=l_day=rec_day;          /* reset first and last day */
               }
            }
         }

         /* check for out of sequence records */
         if (rec_tstamp/3600 < cur_tstamp/3600)
         {
            if (!fold_seq_err && ((rec_tstamp+SLOP_VAL)/3600<cur_tstamp/3600) )
               { total_ignore++; continue; }
            else
            {
               rec_sec   = cur_sec;             /* if folding sequence      */
               rec_min   = cur_min;             /* errors, just make it     */
               rec_hour  = cur_hour;            /* look like the last       */
               rec_day   = cur_day;             /* good records timestamp   */
               rec_month = cur_month;
               rec_year  = cur_year;
               rec_tstamp= cur_tstamp;
            }
         }
         cur_tstamp=rec_tstamp;                 /* update current timestamp */

         /*********************************************/
         /* DO SOME PRE-PROCESS FORMATTING            */
         /*********************************************/

         /* un-escape URL */
         unescape(log_rec.url);

         /* fix URL field */
         cp1 = cp2 = log_rec.url;
         /* handle null '-' case here... */
         if (*++cp1 == '-') strcpy(log_rec.url,"/INVALID-URL");
         else
         {
            /* strip actual URL out of request */
            while  ( (*cp1 != ' ') && (*cp1 != '\0') ) cp1++;
            if (*cp1 != '\0')
            {
               /* scan to begin of actual URL field */
               while ((*cp1 == ' ') && (*cp1 != '\0')) cp1++;
               /* remove duplicate / if needed */
               while (( *cp1=='/') && (*(cp1+1)=='/')) cp1++;
               while (( *cp1!='\0')&&(*cp1!='"')) *cp2++=*cp1++;
               *cp2='\0';
            }
         }

         /* strip query portion of cgi scripts */
         cp1 = log_rec.url;
         while (*cp1 != '\0')
           if (!isurlchar(*cp1, stripcgi)) { *cp1 = '\0'; break; }
           else cp1++;
         if (log_rec.url[0]=='\0')
           { log_rec.url[0]='/'; log_rec.url[1]='\0'; }

         /* Normalize URL */
         if (log_type==LOG_CLF && log_rec.resp_code!=RC_NOTFOUND && normalize)
         {
            if ( ((cp2=strstr(log_rec.url,"://"))!=NULL)&&(cp2<log_rec.url+6) )
            {
               cp1=cp2+3;
               /* see if a '/' is present after it  */
               if ( (cp2=strchr(cp1,(int)'/'))==NULL) cp1--;
               else cp1=cp2;
               /* Ok, now shift url string          */
               cp2=log_rec.url; while (*cp1!='\0') *cp2++=*cp1++; *cp2='\0';
            }
            /* extra sanity checks on URL string */
            while ((cp2=strstr(log_rec.url,"/./")))
               { cp1=cp2+2; while (*cp1!='\0') *cp2++=*cp1++; *cp2='\0'; }
            if (log_rec.url[0]!='/')
            {
               if ( log_rec.resp_code==RC_OK             ||
                    log_rec.resp_code==RC_PARTIALCONTENT ||
                    log_rec.resp_code==RC_NOMOD)
               {
                  if (debug_mode)
                     fprintf(stderr,"Converted URL '%s' to '/'\n",log_rec.url);
                  log_rec.url[0]='/';
                  log_rec.url[1]='\0';
               }
               else
               {
                  if (debug_mode)
                     fprintf(stderr,"Invalid URL: '%s'\n",log_rec.url);
                  strcpy(log_rec.url,"/INVALID-URL");
               }
            }
            while ( log_rec.url[ (i=strlen(log_rec.url)-1) ] == '?' )
               log_rec.url[i]='\0';   /* drop trailing ?s if any */
         }
         else
         {
            /* check for service (ie: http://) and lowercase if found */
            if (((cp2=strstr(log_rec.url,"://"))!= NULL)&&(cp2<log_rec.url+6))
            {
               cp1=log_rec.url;
               while (cp1!=cp2)
               {
                  if ( (*cp1>='A') && (*cp1<='Z')) *cp1 += 'a'-'A';
                  cp1++;
               }
            }
         }

         /* strip off index.html (or any aliases) */
         lptr=index_alias;
         while (lptr!=NULL)
         {
            if ((cp1=strstr(log_rec.url,lptr->string))!=NULL)
            {
               if (*(cp1-1)=='/')
               {
                  if ( !stripcgi && (cp2=strchr(cp1,'?'))!=NULL )
                  { while(*cp2) *cp1++=*cp2++; *cp1='\0'; }
                  else *cp1='\0';
                  break;
               }
            }
            lptr=lptr->next;
         }

         /* unescape referrer */
         unescape(log_rec.refer);

         /* fix referrer field */
         cp1 = log_rec.refer;
         cp3 = cp2 = cp1++;
         if ( (*cp2 != '\0') && (*cp2 == '"') )
         {
            while ( *cp1 != '\0' )
            {
               cp3=cp2;
               if (((unsigned char)*cp1<32&&(unsigned char)*cp1>0) ||
                    *cp1==127 || (unsigned char)*cp1=='<') *cp1=0;
               else *cp2++=*cp1++;
            }
            *cp3 = '\0';
         }

         /* get query portion of cgi referrals */
         cp1 = log_rec.refer;
         if (*cp1 != '\0')
         {
            while (*cp1 != '\0')
            {
               if (!isurlchar(*cp1, 1))
               {
                  /* Save query portion in log.rec.srchstr */
                  strncpy(log_rec.srchstr,(char *)cp1,MAXSRCH);
                  *cp1++='\0';
                  break;
               }
               else cp1++;
            }
            /* handle null referrer */
            if (log_rec.refer[0]=='\0')
              { log_rec.refer[0]='-'; log_rec.refer[1]='\0'; }
         }

         /* if HTTP request, lowercase http://sitename/ portion */
         cp1 = log_rec.refer;
         if ( (*cp1=='h') || (*cp1=='H'))
         {
            while ( (*cp1!='/') && (*cp1!='\0'))
            {
               if ( (*cp1>='A') && (*cp1<='Z')) *cp1 += 'a'-'A';
               cp1++;
            }
            /* now do hostname */
            if ( (*cp1=='/') && ( *(cp1+1)=='/')) {cp1++; cp1++;}
            while ( (*cp1!='/') && (*cp1!='\0'))
            {
               if ( (*cp1>='A') && (*cp1<='Z')) *cp1 += 'a'-'A';
               cp1++;
            }
         }

         /* Do we need to mangle? */
         if (mangle_agent) agent_mangle(log_rec.agent);

         /* if necessary, shrink referrer to fit storage */
         if (strlen(log_rec.refer)>=MAXREFH)
         {
            if (verbose) fprintf(stderr,"%s [%llu]\n",
                msg_big_ref,total_rec);
            log_rec.refer[MAXREFH-1]='\0';
         }

         /* if necessary, shrink URL to fit storage */
         if (strlen(log_rec.url)>=MAXURLH)
         {
            if (verbose) fprintf(stderr,"%s [%llu]\n",
                msg_big_req,total_rec);
            log_rec.url[MAXURLH-1]='\0';
         }

         /* fix user agent field */
         cp1 = log_rec.agent;
         cp3 = cp2 = cp1++;
         if ( (*cp2 != '\0') && ((*cp2 == '"')||(*cp2 == '(')) )
         {
            while (*cp1 != '\0') { cp3 = cp2; *cp2++ = *cp1++; }
            *cp3 = '\0';
         }
         cp1 = log_rec.agent;    /* CHANGE !!! */
         while (*cp1 != 0)       /* get rid of more common _bad_ chars ;)   */
         {
            if ( ((unsigned char)*cp1 < 32) ||
                 ((unsigned char)*cp1==127) ||
                 (*cp1=='<') || (*cp1=='>') )
               { *cp1='\0'; break; }
            else cp1++;
         }

         /* fix username if needed */
         if (log_rec.ident[0]==0)
          {  log_rec.ident[0]='-'; log_rec.ident[1]='\0'; }
         else
         {
            cp3=log_rec.ident;
            while ((unsigned char)*cp3>=32 && *cp3!='"') cp3++;
            *cp3='\0';
         }
         /* unescape user name */
         unescape(log_rec.ident);

         /********************************************/
         /* PROCESS RECORD                           */
         /********************************************/

         /* first time through? */
         if (cur_month == 0)
         {
             /* if yes, init our date vars */
             cur_month=rec_month; cur_year=rec_year;
             cur_day=rec_day; cur_hour=rec_hour;
             cur_min=rec_min; cur_sec=rec_sec;
             f_day=rec_day;
         }

         /* adjust last day processed if different */
         if (rec_day > l_day) l_day = rec_day;
 
         /* update min/sec stuff */
         if (cur_sec != rec_sec) cur_sec = rec_sec;
         if (cur_min != rec_min) cur_min = rec_min;

         /* check for hour change  */
         if (cur_hour != rec_hour)
         {
            /* if yes, init hourly stuff */
            if (ht_hit > mh_hit) mh_hit = ht_hit;
            ht_hit = 0;
            cur_hour = rec_hour;
         }

         /* check for day change   */
         if (cur_day != rec_day)
         {
            /* if yes, init daily stuff */
            tm_site[cur_day-1]=dt_site; dt_site=0;
            tm_visit[cur_day-1]=tot_visit(sd_htab);
            del_hlist(sd_htab);
            cur_day = rec_day;
         }

         /* check for month change */
         if ( (cur_month != rec_month) || (cur_year != rec_year) )
         {
            /* if yes, do monthly stuff */
            t_visit=tot_visit(sm_htab);
            month_update_exit(req_tstamp);    /* process exit pages      */
            update_history();
            write_month_html();               /* generate HTML for month */
            clear_month();
            cur_month = rec_month;            /* update our flags        */
            cur_year  = rec_year;
            f_day=l_day=rec_day;
         }

         /* save hostname for later */
         strncpy(host_buf, log_rec.hostname, sizeof(log_rec.hostname));

#ifdef USE_DNS
         /* Resolve IP address if needed */
         if (dns_db)
         {
            struct addrinfo hints, *ares;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_NUMERICHOST;
            if (0 == getaddrinfo(log_rec.hostname, "0", &hints, &ares))
            {
               freeaddrinfo(ares);
               resolve_dns(&log_rec);
            }
         }
#endif
         /* lowercase hostname and validity check */
         cp1 = log_rec.hostname; i=0;

         if ( (!isalnum((unsigned char)*cp1)) && (*cp1!=':') )
            strncpy(log_rec.hostname, "Invalid", 8);
         else
         {
            while (*cp1 != '\0')  /* loop through string */
            {
               if ( (*cp1>='A') && (*cp1<='Z') )
                  { *cp1++ += 'a'-'A'; continue; }
               if ( *cp1=='.' ) i++;
               if ( (isalnum((unsigned char)*cp1)) ||
                    (*cp1=='.')||(*cp1=='-')       ||
                    (*cp1==':')||((*cp1=='_')&&(i==0)) ) cp1++;
               else
               {
                  /* Invalid hostname found! */
                  if (strcmp(log_rec.hostname, host_buf))
                     strcpy(log_rec.hostname, host_buf);
                  else strncpy(log_rec.hostname,"Invalid",8);
                  break;
               }
            }
            if (*cp1 == '\0')   /* did we make it to the end? */
            {
               if (!isalnum((unsigned char)*(cp1-1)))
                  strncpy(log_rec.hostname,"Invalid",8);
            }
         }

         /* Catch blank hostnames here */
         if (log_rec.hostname[0]=='\0')
            strncpy(log_rec.hostname,"Unknown",8);

         /* Ignore/Include check */
         if ( (isinlist(include_sites,log_rec.hostname)==NULL) &&
              (isinlist(include_urls,log_rec.url)==NULL)       &&
              (isinlist(include_refs,log_rec.refer)==NULL)     &&
              (isinlist(include_agents,log_rec.agent)==NULL)   &&
              (isinlist(include_users,log_rec.ident)==NULL)    )
         {
            if (isinlist(ignored_sites,log_rec.hostname)!=NULL)
              { total_ignore++; continue; }
            if (isinlist(ignored_urls,log_rec.url)!=NULL)
              { total_ignore++; continue; }
            if (isinlist(ignored_agents,log_rec.agent)!=NULL)
              { total_ignore++; continue; }
            if (isinlist(ignored_refs,log_rec.refer)!=NULL)
              { total_ignore++; continue; }
            if (isinlist(ignored_users,log_rec.ident)!=NULL)
              { total_ignore++; continue; }
         }

         /* Bump response code totals */
         switch (log_rec.resp_code) {
          case RC_CONTINUE:         i=IDX_CONTINUE;         break;
          case RC_SWITCHPROTO:      i=IDX_SWITCHPROTO;      break;
          case RC_OK:               i=IDX_OK;               break;
          case RC_CREATED:          i=IDX_CREATED;          break;
          case RC_ACCEPTED:         i=IDX_ACCEPTED;         break;
          case RC_NONAUTHINFO:      i=IDX_NONAUTHINFO;      break;
          case RC_NOCONTENT:        i=IDX_NOCONTENT;        break;
          case RC_RESETCONTENT:     i=IDX_RESETCONTENT;     break;
          case RC_PARTIALCONTENT:   i=IDX_PARTIALCONTENT;   break;
          case RC_MULTIPLECHOICES:  i=IDX_MULTIPLECHOICES;  break;
          case RC_MOVEDPERM:        i=IDX_MOVEDPERM;        break;
          case RC_MOVEDTEMP:        i=IDX_MOVEDTEMP;        break;
          case RC_SEEOTHER:         i=IDX_SEEOTHER;         break;
          case RC_NOMOD:            i=IDX_NOMOD;            break;
          case RC_USEPROXY:         i=IDX_USEPROXY;         break;
 	  case RC_MOVEDTEMPORARILY: i=IDX_MOVEDTEMPORARILY; break;
          case RC_BAD:              i=IDX_BAD;              break;
          case RC_UNAUTH:           i=IDX_UNAUTH;           break;
          case RC_PAYMENTREQ:       i=IDX_PAYMENTREQ;       break;
          case RC_FORBIDDEN:        i=IDX_FORBIDDEN;        break;
          case RC_NOTFOUND:         i=IDX_NOTFOUND;         break;
          case RC_METHODNOTALLOWED: i=IDX_METHODNOTALLOWED; break;
          case RC_NOTACCEPTABLE:    i=IDX_NOTACCEPTABLE;    break;
          case RC_PROXYAUTHREQ:     i=IDX_PROXYAUTHREQ;     break;
          case RC_TIMEOUT:          i=IDX_TIMEOUT;          break;
          case RC_CONFLICT:         i=IDX_CONFLICT;         break;
          case RC_GONE:             i=IDX_GONE;             break;
          case RC_LENGTHREQ:        i=IDX_LENGTHREQ;        break;
          case RC_PREFAILED:        i=IDX_PREFAILED;        break;
          case RC_REQENTTOOLARGE:   i=IDX_REQENTTOOLARGE;   break;
          case RC_REQURITOOLARGE:   i=IDX_REQURITOOLARGE;   break;
          case RC_UNSUPMEDIATYPE:   i=IDX_UNSUPMEDIATYPE;   break;
	  case RC_RNGNOTSATISFIABLE:i=IDX_RNGNOTSATISFIABLE;break;
	  case RC_EXPECTATIONFAILED:i=IDX_EXPECTATIONFAILED;break;
          case RC_SERVERERR:        i=IDX_SERVERERR;        break;
          case RC_NOTIMPLEMENTED:   i=IDX_NOTIMPLEMENTED;   break;
          case RC_BADGATEWAY:       i=IDX_BADGATEWAY;       break;
          case RC_UNAVAIL:          i=IDX_UNAVAIL;          break;
          case RC_GATEWAYTIMEOUT:   i=IDX_GATEWAYTIMEOUT;   break;
          case RC_BADHTTPVER:       i=IDX_BADHTTPVER;       break;
          default:                  i=IDX_UNDEFINED;        break;
         }
         response[i].count++;

         /* now save in the various hash tables... */
         if (log_rec.resp_code==RC_OK || log_rec.resp_code==RC_PARTIALCONTENT)
            i=1; else i=0;
         
         /* URL/ident hash table (only if valid response code) */
         if ((log_rec.resp_code==RC_OK)||(log_rec.resp_code==RC_NOMOD)||
             (log_rec.resp_code==RC_PARTIALCONTENT))
         {
            /* URL hash table */
            if (put_unode(log_rec.url,OBJ_REG,(u_int64_t)1,
                log_rec.xfer_size,&t_url,(u_int64_t)0,(u_int64_t)0,um_htab))
            {
               if (verbose)
               /* Error adding URL node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_u, log_rec.url);
            }

            /* ident (username) hash table */
            if (put_inode(log_rec.ident,OBJ_REG,
                1,(u_int64_t)i,log_rec.xfer_size,&t_user,
                0,rec_tstamp,im_htab))
            {
               if (verbose)
               /* Error adding ident node, skipping .... */
               fprintf(stderr,"%s %s\n", msg_nomem_i, log_rec.ident);
            }
         }

         /* referrer hash table */
         if (ntop_refs)
         {
            if (log_rec.refer[0]!='\0')
             if (put_rnode(log_rec.refer,OBJ_REG,(u_int64_t)1,&t_ref,rm_htab))
             {
              if (verbose)
              fprintf(stderr,"%s %s\n", msg_nomem_r, log_rec.refer);
             }
         }

         /* hostname (site) hash table - daily */
         if (put_hnode(log_rec.hostname,OBJ_REG,
             1,(u_int64_t)i,log_rec.xfer_size,&dt_site,
             0,rec_tstamp,"",sd_htab))
         {
            if (verbose)
            /* Error adding host node (daily), skipping .... */
            fprintf(stderr,"%s %s\n",msg_nomem_dh, log_rec.hostname);
         }

         /* hostname (site) hash table - monthly */
         if (put_hnode(log_rec.hostname,OBJ_REG,
             1,(u_int64_t)i,log_rec.xfer_size,&t_site,
             0,rec_tstamp,"",sm_htab))
         {
            if (verbose)
            /* Error adding host node (monthly), skipping .... */
            fprintf(stderr,"%s %s\n", msg_nomem_mh, log_rec.hostname);
         }

         /* user agent hash table */
         if (ntop_agents)
         {
            if (log_rec.agent[0]!='\0')
             if (put_anode(log_rec.agent,OBJ_REG,(u_int64_t)1,&t_agent,am_htab))
             {
              if (verbose)
              fprintf(stderr,"%s %s\n", msg_nomem_a, log_rec.agent);
             }
         }

         /* bump monthly/daily/hourly totals        */
         t_hit++; ht_hit++;                         /* daily/hourly hits    */
         t_xfer += log_rec.xfer_size;               /* total xfer size      */
         tm_xfer[rec_day-1] += log_rec.xfer_size;   /* daily xfer total     */
         tm_hit[rec_day-1]++;                       /* daily hits total     */
         th_xfer[rec_hour] += log_rec.xfer_size;    /* hourly xfer total    */
         th_hit[rec_hour]++;                        /* hourly hits total    */
   
         /* if RC_OK, increase file counters */
         if (log_rec.resp_code == RC_OK)
         {
            t_file++;
            tm_file[rec_day-1]++;
            th_file[rec_hour]++;
         }

         /* Pages (pageview) calculation */
         if (ispage(log_rec.url))
         {
            t_page++;
            tm_page[rec_day-1]++;
            th_page[rec_hour]++;

            /* do search string stuff if needed     */
            if (ntop_search) srch_string(log_rec.srchstr);
         }

         /*********************************************/
         /* RECORD PROCESSED - DO GROUPS HERE         */ 
         /*********************************************/

         /* URL Grouping */
         if ( (cp1=isinglist(group_urls,log_rec.url))!=NULL)
         {
            if (put_unode(cp1,OBJ_GRP,(u_int64_t)1,log_rec.xfer_size,
                &ul_bogus,(u_int64_t)0,(u_int64_t)0,um_htab))
            {
               if (verbose)
               /* Error adding URL node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_u, cp1);
            }
         }

         /* Site Grouping */
         if ( (cp1=isinglist(group_sites,log_rec.hostname))!=NULL)
         {
            if (put_hnode(cp1,OBJ_GRP,1,
                          (u_int64_t)(log_rec.resp_code==RC_OK)?1:0,
                          log_rec.xfer_size,&ul_bogus,
                          0,rec_tstamp,"",sm_htab))
            {
               if (verbose)
               /* Error adding Site node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_mh, cp1);
            }
         }
         else
         {
            /* Domain Grouping */
            if (group_domains)
            {
               cp1 = get_domain(log_rec.hostname);
               if (cp1 != NULL)
               {
                  if (put_hnode(cp1,OBJ_GRP,1,
                      (u_int64_t)(log_rec.resp_code==RC_OK)?1:0,
                      log_rec.xfer_size,&ul_bogus,
                      0,rec_tstamp,"",sm_htab))
                  {
                     if (verbose)
                     /* Error adding Site node, skipping ... */
                     fprintf(stderr,"%s %s\n", msg_nomem_mh, cp1);
                  }
               }
            }
         }

         /* Referrer Grouping */
         if ( (cp1=isinglist(group_refs,log_rec.refer))!=NULL)
         {
            if (put_rnode(cp1,OBJ_GRP,(u_int64_t)1,&ul_bogus,rm_htab))
            {
               if (verbose)
               /* Error adding Referrer node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_r, cp1);
            }
         }

         /* User Agent Grouping */
         if ( (cp1=isinglist(group_agents,log_rec.agent))!=NULL)
         {
            if (put_anode(cp1,OBJ_GRP,(u_int64_t)1,&ul_bogus,am_htab))
            {
               if (verbose)
               /* Error adding User Agent node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_a, cp1);
            }
         }

         /* Ident (username) Grouping */
         if ( (cp1=isinglist(group_users,log_rec.ident))!=NULL)
         {
            if (put_inode(cp1,OBJ_GRP,1,
                          (u_int64_t)(log_rec.resp_code==RC_OK)?1:0,
                          log_rec.xfer_size,&ul_bogus,
                          0,rec_tstamp,im_htab))
            {
               if (verbose)
               /* Error adding Username node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_i, cp1);
            }
         }
      }

      /*********************************************/
      /* BAD RECORD                                */
      /*********************************************/

      else
      {
         /* If first record, check if stupid Netscape header stuff      */
         if ( (total_rec==1) && (strncmp(buffer,"format=",7)==0) )
         {
            /* Skipping Netscape header record */
            if (verbose>1) printf("%s\n",msg_ign_nscp);
            /* count it as ignored... */
            total_ignore++;
         }
         else
         {
            /* Check if it's a W3C header or IIS Null-Character line */
            if ((buffer[0]=='\0') || (buffer[0]=='#'))
            {
               total_ignore++;
            }
            else
            {
               /* really bad record... */
               total_bad++;
               if (verbose)
               {
                  fprintf(stderr,"%s (%llu)",msg_bad_rec,total_rec);
                  if (debug_mode) fprintf(stderr,":\n%s\n",tmp_buf);
                  else fprintf(stderr,"\n");
               }
            }
         }
      }
   }

   /*********************************************/
   /* DONE READING LOG FILE - final processing  */
   /*********************************************/

   /* close log file if needed */
#ifdef USE_BZIP
   if (gz_log) (gz_log==COMP_BZIP)?BZ2_bzclose(zlog_fp):gzclose(zlog_fp);
#else
   if (gz_log) gzclose(zlog_fp);
#endif
   else if (log_fname) fclose(log_fp);

   if (good_rec)                             /* were any good records?   */
   {
      tm_site[cur_day-1]=dt_site;            /* If yes, clean up a bit   */
      tm_visit[cur_day-1]=tot_visit(sd_htab);
      t_visit=tot_visit(sm_htab);
      if (ht_hit > mh_hit) mh_hit = ht_hit;

      if (total_rec > (total_ignore+total_bad)) /* did we process any?   */
      {
         if (incremental)
         {
            if (save_state())                /* incremental stuff        */
            {
               /* Error: Unable to save current run data */
               if (verbose) fprintf(stderr,"%s\n",msg_data_err);
               unlink(state_fname);
            }
         }
         month_update_exit(rec_tstamp);      /* calculate exit pages     */
         update_history();
         write_month_html();                 /* write monthly HTML file  */
         put_history();                      /* write history            */
      }
      if (hist[0].month!=0) write_main_index(); /* write main HTML file  */

      /* get processing end time */
      end_time = time(NULL);

      /* display end of processing statistics */
      if (time_me || (verbose>1))
      {
         printf("%llu %s ",total_rec, msg_records);
         if (total_ignore)
         {
            printf("(%llu %s",total_ignore,msg_ignored);
            if (total_bad) printf(", %llu %s) ",total_bad,msg_bad);
               else        printf(") ");
         }
         else if (total_bad) printf("(%llu %s) ",total_bad,msg_bad);

         /* totoal processing time in seconds */
         temp_time = difftime(end_time, start_time);
         if (temp_time==0) temp_time=1;
         printf("%s %.0f %s", msg_in, temp_time, msg_seconds);

         /* calculate records per second */
         if (temp_time)
           i=( (int)( (float)total_rec/temp_time ) );
         else i=0;

         if ( (i>0) && (i<=total_rec) ) printf(", %d/sec\n", i);
            else  printf("\n");
      }

#ifdef USE_DNS
      /* Close DNS cache file */
      if (dns_db) close_cache();
      /* Close GeoDB database */
      if (geo_db) geodb_close(geo_db);
#endif

#ifdef USE_GEOIP
      /* Close GeoIP database */
      if (geo_fp) GeoIP_delete(geo_fp);
#endif

      /* Whew, all done! Exit with completion status (0) */
      exit(0);
   }
   else
   {
      /* No valid records found... exit with error (1) */
      if (verbose) printf("%s\n",msg_no_vrec);
      if (hist[0].month!=0) write_main_index(); /* write main HTML file     */
      exit(1);
   }
}

/*********************************************/
/* GET_CONFIG - get configuration file info  */
/*********************************************/

void get_config(char *fname)
{
   char *kwords[]= { "Undefined",         /* 0 = undefined keyword       0  */
                     "OutputDir",         /* Output directory            1  */
                     "LogFile",           /* Log file to use for input   2  */
                     "ReportTitle",       /* Title for reports           3  */
                     "HostName",          /* Hostname to use             4  */
                     "IgnoreHist",        /* Ignore history file         5  */
                     "Quiet",             /* Run in quiet mode           6  */
                     "TimeMe",            /* Produce timing results      7  */
                     "Debug",             /* Produce debug information   8  */
                     "HourlyGraph",       /* Hourly stats graph          9  */
                     "HourlyStats",       /* Hourly stats table         10  */
                     "TopSites",          /* Top sites                  11  */
                     "TopURLs",           /* Top URLs                   12  */
                     "TopReferrers",      /* Top Referrers              13  */
                     "TopAgents",         /* Top User Agents            14  */
                     "TopCountries",      /* Top Countries              15  */
                     "HideSite",          /* Sites to hide              16  */
                     "HideURL",           /* URLs to hide               17  */
                     "HideReferrer",      /* Referrers to hide          18  */
                     "HideAgent",         /* User Agents to hide        19  */
                     "IndexAlias",        /* Aliases for index.html     20  */
                     "HTMLHead",          /* HTML Top1 code             21  */
                     "HTMLPost",          /* HTML Top2 code             22  */
                     "HTMLTail",          /* HTML Tail code             23  */
                     "MangleAgents",      /* Mangle User Agents         24  */
                     "IgnoreSite",        /* Sites to ignore            25  */
                     "IgnoreURL",         /* Url's to ignore            26  */
                     "IgnoreReferrer",    /* Referrers to ignore        27  */
                     "IgnoreAgent",       /* User Agents to ignore      28  */
                     "ReallyQuiet",       /* Dont display ANY messages  29  */
                     "GMTTime",           /* Local or UTC time?         30  */
                     "GroupURL",          /* Group URLs                 31  */
                     "GroupSite",         /* Group Sites                32  */
                     "GroupReferrer",     /* Group Referrers            33  */
                     "GroupAgent",        /* Group Agents               34  */
                     "GroupShading",      /* Shade Grouped entries      35  */
                     "GroupHighlight",    /* BOLD Grouped entries       36  */
                     "Incremental",       /* Incremental runs           37  */
                     "IncrementalName",   /* Filename for state data    38  */
                     "HistoryName",       /* Filename for history data  39  */
                     "HTMLExtension",     /* HTML filename extension    40  */
                     "HTMLPre",           /* HTML code at beginning     41  */
                     "HTMLBody",          /* HTML body code             42  */
                     "HTMLEnd",           /* HTML code at end           43  */
                     "UseHTTPS",          /* Use https:// on URLs       44  */
                     "IncludeSite",       /* Sites to always include    45  */
                     "IncludeURL",        /* URLs to always include     46  */
                     "IncludeReferrer",   /* Referrers to include       47  */
                     "IncludeAgent",      /* User Agents to include     48  */
                     "PageType",          /* Page Type (pageview)       49  */
                     "VisitTimeout",      /* Visit timeout (seconds)    50  */
                     "GraphLegend",       /* Graph Legends (yes/no)     51  */
                     "GraphLines",        /* Graph Lines (0=none)       52  */
                     "FoldSeqErr",        /* Fold sequence errors       53  */
                     "CountryGraph",      /* Display ctry graph (0=no)  54  */
                     "TopKSites",         /* Top sites (by KBytes)      55  */
                     "TopKURLs",          /* Top URLs  (by KBytes)      56  */
                     "TopEntry",          /* Top Entry Pages            57  */
                     "TopExit",           /* Top Exit Pages             58  */
                     "TopSearch",         /* Top Search Strings         59  */
                     "LogType",           /* Log Type (clf/ftp/squid)   60  */
                     "SearchEngine",      /* SearchEngine strings       61  */
                     "GroupDomains",      /* Group domains (n=level)    62  */
                     "HideAllSites",      /* Hide ind. sites (0=no)     63  */
                     "AllSites",          /* List all sites?            64  */
                     "AllURLs",           /* List all URLs?             65  */
                     "AllReferrers",      /* List all Referrers?        66  */
                     "AllAgents",         /* List all User Agents?      67  */
                     "AllSearchStr",      /* List all Search Strings?   68  */
                     "AllUsers",          /* List all Users?            69  */
                     "TopUsers",          /* Top Usernames to show      70  */
                     "HideUser",          /* Usernames to hide          71  */
                     "IgnoreUser",        /* Usernames to ignore        72  */
                     "IncludeUser",       /* Usernames to include       73  */
                     "GroupUser",         /* Usernames to group         74  */
                     "DumpPath",          /* Path for dump files        75  */
                     "DumpExtension",     /* Dump filename extension    76  */
                     "DumpHeader",        /* Dump header as first rec?  77  */
                     "DumpSites",         /* Dump sites tab file        78  */
                     "DumpURLs",          /* Dump urls tab file         79  */
                     "DumpReferrers",     /* Dump referrers tab file    80  */
                     "DumpAgents",        /* Dump user agents tab file  81  */
                     "DumpUsers",         /* Dump usernames tab file    82  */
                     "DumpSearchStr",     /* Dump search str tab file   83  */
                     "DNSCache",          /* DNS Cache file name        84  */
                     "DNSChildren",       /* DNS Children (0=no DNS)    85  */
                     "DailyGraph",        /* Daily Graph (0=no)         86  */
                     "DailyStats",        /* Daily Stats (0=no)         87  */
                     "LinkReferrer",      /* Link referrer (0=no)       88  */
                     "PagePrefix",        /* PagePrefix - treat as page 89  */
                     "ColorHit",          /* Hit Color   (def=00805c)   90  */
                     "ColorFile",         /* File Color  (def=0040ff)   91  */
                     "ColorSite",         /* Site Color  (def=ff8000)   92  */
                     "ColorKbyte",        /* Kbyte Color (def=ff0000)   93  */
                     "ColorPage",         /* Page Color  (def=00e0ff)   94  */
                     "ColorVisit",        /* Visit Color (def=ffff00)   95  */
                     "ColorMisc",         /* Misc Color  (def=00e0ff)   96  */
                     "PieColor1",         /* Pie Color 1 (def=800080)   97  */
                     "PieColor2",         /* Pie Color 2 (def=80ffc0)   98  */
                     "PieColor3",         /* Pie Color 3 (def=ff00ff)   99  */
                     "PieColor4",         /* Pie Color 4 (def=ffc080)   100 */
                     "CacheIPs",          /* Cache IPs in DNS DB (0=no) 101 */
                     "CacheTTL",          /* DNS Cache entry TTL (days) 102 */
                     "GeoDB",             /* GeoDB lookups (0=no)       103 */
                     "GeoDBDatabase",     /* GeoDB database filename    104 */
                     "StripCGI",          /* Strip CGI in URLS (0=no)   105 */
                     "TrimSquidURL",      /* Trim squid URLs (0=none)   106 */
                     "OmitPage",          /* URLs not counted as pages  107 */
                     "HTAccess",          /* Write .httaccess files?    108 */
                     "IgnoreState",       /* Ignore state file (0=no)   109 */
                     "DefaultIndex",      /* Default index.* (1=yes)    110 */
                     "GeoIP",             /* Use GeoIP? (1=yes)         111 */
                     "GeoIPDatabase",     /* Database to use for GeoIP  112 */
                     "NormalizeURL",      /* Normalize CLF URLs (1=yes) 113 */
                     "IndexMonths",       /* # months for main page     114 */
                     "GraphMonths",       /* # months for yearly graph  115 */
                     "YearHeaders",       /* use year headers? (1=yes)  116 */
                     "YearTotals",        /* show year subtotals (0=no) 117 */
                     "CountryFlags",      /* show country flags? (0-no) 118 */
                     "FlagDir",           /* directory w/flag images    119 */
                     "SearchCaseI"        /* srch str case insensitive  120 */
                   };

   FILE *fp;

   char buffer[BUFSIZE];
   char keyword[MAXKWORD];
   char value[MAXKVAL];
   char *cp1, *cp2;
   int  i,key,count;
   int	num_kwords=sizeof(kwords)/sizeof(char *);

   if ( (fp=fopen(fname,"r")) == NULL)
   {
      if (verbose)
      fprintf(stderr,"%s %s\n",msg_bad_conf,fname);
      return;
   }

   while ( (fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      /* skip comments and blank lines */
      if ( (buffer[0]=='#') || isspace((unsigned char)buffer[0]) ) continue;

      /* Get keyword */
      cp1=buffer;cp2=keyword;count=MAXKWORD-1;
      while ( (isalnum((unsigned char)*cp1)) && count )
         { *cp2++ = *cp1++; count--; }
      *cp2='\0';

      /* Get value */
      cp2=value; count=MAXKVAL-1;
      while ((*cp1!='\n')&&(*cp1!='\0')&&(isspace((unsigned char)*cp1))) cp1++;
      while ((*cp1!='\n')&&(*cp1!='\0')&&count ) { *cp2++ = *cp1++; count--; }
      *cp2--='\0';
      while ((isspace((unsigned char)*cp2)) && (cp2 != value) ) *cp2--='\0';

      /* check if blank keyword/value */
      if ( (keyword[0]=='\0') || (value[0]=='\0') ) continue;

      key=0;
      for (i=0;i<num_kwords;i++)
         if (!ouricmp(keyword,kwords[i])) { key=i; break; }

      if (key==0) { printf("%s '%s' (%s)\n",       /* Invalid keyword       */
                    msg_bad_key,keyword,fname);
                    continue;
                  }

      switch (key)
      {
        case 1:  out_dir=save_opt(value);          break; /* OutputDir      */
        case 2:  log_fname=save_opt(value);        break; /* LogFile        */
        case 3:  msg_title=save_opt(value);        break; /* ReportTitle    */
        case 4:  hname=save_opt(value);            break; /* HostName       */
        case 5:  ignore_hist=
                    (tolower(value[0])=='y')?1:0;  break; /* IgnoreHist     */
        case 6:  verbose=
                    (tolower(value[0])=='y')?1:2;  break; /* Quiet          */
        case 7:  time_me=
                    (tolower(value[0])=='n')?0:1;  break; /* TimeMe         */
        case 8:  debug_mode=
                    (tolower(value[0])=='y')?1:0;  break; /* Debug          */
        case 9:  hourly_graph=
                    (tolower(value[0])=='n')?0:1;  break; /* HourlyGraph    */
        case 10: hourly_stats=
                    (tolower(value[0])=='n')?0:1;  break; /* HourlyStats    */
        case 11: ntop_sites = atoi(value);         break; /* TopSites       */
        case 12: ntop_urls = atoi(value);          break; /* TopURLs        */
        case 13: ntop_refs = atoi(value);          break; /* TopRefs        */
        case 14: ntop_agents = atoi(value);        break; /* TopAgents      */
        case 15: ntop_ctrys = atoi(value);         break; /* TopCountries   */
        case 16: add_nlist(value,&hidden_sites);   break; /* HideSite       */
        case 17: add_nlist(value,&hidden_urls);    break; /* HideURL        */
        case 18: add_nlist(value,&hidden_refs);    break; /* HideReferrer   */
        case 19: add_nlist(value,&hidden_agents);  break; /* HideAgent      */
        case 20: add_nlist(value,&index_alias);    break; /* IndexAlias     */
        case 21: add_nlist(value,&html_head);      break; /* HTMLHead       */
        case 22: add_nlist(value,&html_post);      break; /* HTMLPost       */
        case 23: add_nlist(value,&html_tail);      break; /* HTMLTail       */
        case 24: mangle_agent=atoi(value);         break; /* MangleAgents   */
        case 25: add_nlist(value,&ignored_sites);  break; /* IgnoreSite     */
        case 26: add_nlist(value,&ignored_urls);   break; /* IgnoreURL      */
        case 27: add_nlist(value,&ignored_refs);   break; /* IgnoreReferrer */
        case 28: add_nlist(value,&ignored_agents); break; /* IgnoreAgent    */
        case 29: if (tolower(value[0])=='y')
                    verbose=0;                     break; /* ReallyQuiet    */
        case 30: local_time=
                    (tolower(value[0])=='y')?0:1;  break; /* GMTTime        */
        case 31: add_glist(value,&group_urls);     break; /* GroupURL       */
        case 32: add_glist(value,&group_sites);    break; /* GroupSite      */
        case 33: add_glist(value,&group_refs);     break; /* GroupReferrer  */
        case 34: add_glist(value,&group_agents);   break; /* GroupAgent     */
        case 35: shade_groups=
                    (tolower(value[0])=='n')?0:1;  break; /* GroupShading   */
        case 36: hlite_groups=
                    (tolower(value[0])=='n')?0:1;  break; /* GroupHighlight */
        case 37: incremental=
                    (tolower(value[0])=='y')?1:0;  break; /* Incremental    */
        case 38: state_fname=save_opt(value);      break; /* State FName    */
        case 39: hist_fname=save_opt(value);       break; /* History FName  */
        case 40: html_ext=save_opt(value);         break; /* HTML extension */
        case 41: add_nlist(value,&html_pre);       break; /* HTML Pre code  */
        case 42: add_nlist(value,&html_body);      break; /* HTML Body code */
        case 43: add_nlist(value,&html_end);       break; /* HTML End code  */
        case 44: use_https=
                    (tolower(value[0])=='y')?1:0;  break; /* Use https://   */
        case 45: add_nlist(value,&include_sites);  break; /* IncludeSite    */
        case 46: add_nlist(value,&include_urls);   break; /* IncludeURL     */
        case 47: add_nlist(value,&include_refs);   break; /* IncludeReferrer*/
        case 48: add_nlist(value,&include_agents); break; /* IncludeAgent   */
        case 49: add_nlist(value,&page_type);      break; /* PageType       */
        case 50: visit_timeout=atoi(value);        break; /* VisitTimeout   */
        case 51: graph_legend=
                    (tolower(value[0])=='n')?0:1;  break; /* GraphLegend    */
        case 52: graph_lines = atoi(value);        break; /* GraphLines     */
        case 53: fold_seq_err=
                    (tolower(value[0])=='y')?1:0;  break; /* FoldSeqErr     */
        case 54: ctry_graph=
                    (tolower(value[0])=='n')?0:1;  break; /* CountryGraph   */
        case 55: ntop_sitesK = atoi(value);        break; /* TopKSites (KB) */
        case 56: ntop_urlsK  = atoi(value);        break; /* TopKUrls (KB)  */
        case 57: ntop_entry  = atoi(value);        break; /* Top Entry pgs  */
        case 58: ntop_exit   = atoi(value);        break; /* Top Exit pages */
        case 59: ntop_search = atoi(value);        break; /* Top Search pgs */
        case 60: log_type=(tolower(value[0])=='f')?
                 LOG_FTP:((tolower(value[0])=='s')?
                 LOG_SQUID:((tolower(value[0])=='w')?
                 LOG_W3C:LOG_CLF));                break; /* LogType        */
        case 61: add_glist(value,&search_list);    break; /* SearchEngine   */
        case 62: group_domains=atoi(value);        break; /* GroupDomains   */
        case 63: hide_sites=
                    (tolower(value[0])=='y')?1:0;  break; /* HideAllSites   */
        case 64: all_sites=
                    (tolower(value[0])=='y')?1:0;  break; /* All Sites?     */
        case 65: all_urls=
                    (tolower(value[0])=='y')?1:0;  break; /* All URLs?      */
        case 66: all_refs=
                    (tolower(value[0])=='y')?1:0;  break; /* All Refs       */
        case 67: all_agents=
                    (tolower(value[0])=='y')?1:0;  break; /* All Agents?    */
        case 68: all_search=
                    (tolower(value[0])=='y')?1:0;  break; /* All Srch str   */
        case 69: all_users=
                    (tolower(value[0])=='y')?1:0;  break; /* All Users?     */
        case 70: ntop_users=atoi(value);           break; /* TopUsers       */
        case 71: add_nlist(value,&hidden_users);   break; /* HideUser       */
        case 72: add_nlist(value,&ignored_users);  break; /* IgnoreUser     */
        case 73: add_nlist(value,&include_users);  break; /* IncludeUser    */
        case 74: add_glist(value,&group_users);    break; /* GroupUser      */
        case 75: dump_path=save_opt(value);        break; /* DumpPath       */
        case 76: dump_ext=save_opt(value);         break; /* Dumpfile ext   */
        case 77: dump_header=
                    (tolower(value[0])=='y')?1:0;  break; /* DumpHeader?    */
        case 78: dump_sites=
                    (tolower(value[0])=='y')?1:0;  break; /* DumpSites?     */
        case 79: dump_urls=
                    (tolower(value[0])=='y')?1:0;  break; /* DumpURLs?      */
        case 80: dump_refs=
                    (tolower(value[0])=='y')?1:0;  break; /* DumpReferrers? */
        case 81: dump_agents=
                    (tolower(value[0])=='y')?1:0;  break; /* DumpAgents?    */
        case 82: dump_users=
                    (tolower(value[0])=='y')?1:0;  break; /* DumpUsers?     */
        case 83: dump_search=
                    (tolower(value[0])=='y')?1:0;  break; /* DumpSrchStrs?  */
#ifdef USE_DNS
        case 84: dns_cache=save_opt(value);        break; /* DNSCache fname */
        case 85: dns_children=atoi(value);         break; /* DNSChildren    */
#else
        case 84: /* Disable DNSCache and DNSChildren if DNS is not enabled  */
        case 85: printf("%s '%s' (%s)\n",msg_bad_key,keyword,fname); break;
#endif  /* USE_DNS */
        case 86: daily_graph=
                    (tolower(value[0])=='n')?0:1;  break; /* HourlyGraph    */
        case 87: daily_stats=
                    (tolower(value[0])=='n')?0:1;  break; /* HourlyStats    */
        case 88: link_referrer=
                    (tolower(value[0])=='y')?1:0;  break; /* LinkReferrer   */
        case 89: add_nlist(value,&page_prefix);    break; /* PagePrefix     */
        case 90: strncpy(hit_color+1,  value, 6);  break; /* ColorHit       */
        case 91: strncpy(file_color+1, value, 6);  break; /* ColorFile      */
        case 92: strncpy(site_color+1, value, 6);  break; /* ColorSite      */
        case 93: strncpy(kbyte_color+1,value, 6);  break; /* ColorKbyte     */
        case 94: strncpy(page_color+1, value, 6);  break; /* ColorPage      */
        case 95: strncpy(visit_color+1,value, 6);  break; /* ColorVisit     */
        case 96: strncpy(misc_color+1, value, 6);  break; /* ColorMisc      */
        case 97: strncpy(pie_color1+1, value, 6);  break; /* PieColor1      */
        case 98: strncpy(pie_color2+1, value, 6);  break; /* PieColor2      */
        case 99: strncpy(pie_color3+1, value, 6);  break; /* PieColor3      */
        case 100:strncpy(pie_color4+1, value, 6);  break; /* PieColor4      */
#ifdef USE_DNS
        case 101: cache_ips=
                    (tolower(value[0])=='y')?1:0;  break; /* CacheIPs       */
        case 102: cache_ttl=atoi(value);           break; /* CacheTTL days  */
        case 103: geodb=
                    (tolower(value[0])=='y')?1:0;  break; /* GeoDB          */
        case 104: geodb_fname=save_opt(value);     break; /* GeoDBDatabase  */
#else
        case 101: /* Disable CacheIPs/CacheTTL/GeoDB/GeoDBDatabase if none  */
        case 102: 
        case 103:
        case 104: printf("%s '%s' (%s)\n",msg_bad_key,keyword,fname); break;
#endif  /* USE_DNS */
        case 105: stripcgi=
                    (tolower(value[0])=='n')?0:1;  break; /* StripCGI       */
        case 106: trimsquid=atoi(value);           break; /* TrimSquidURL   */
        case 107: add_nlist(value,&omit_page);     break; /* OmitPage       */
        case 108: htaccess=
                    (tolower(value[0])=='y')?1:0;  break; /* HTAccess       */
        case 109: ignore_state=
                    (tolower(value[0])=='y')?1:0;  break; /* IgnoreState    */
        case 110: default_index=
                    (tolower(value[0])=='n')?0:1;  break; /* DefaultIndex   */
#ifdef USE_GEOIP
        case 111: geoip=
                    (tolower(value[0])=='y')?1:0;  break; /* GeoIP          */
        case 112: geoip_db=save_opt(value);        break; /* GeoIPDatabase  */
#else
        case 111: /* Disable GeoIP and GeoIPDatabase if not enabled         */
        case 112: printf("%s '%s' (%s)\n",msg_bad_key,keyword,fname); break;
#endif
        case 113: normalize=
                    (tolower(value[0])=='n')?0:1;  break; /* NormalizeURL   */
        case 114: index_mths=atoi(value);          break; /* IndexMonths    */
        case 115: graph_mths=atoi(value);          break; /* GraphMonths    */
        case 116: year_hdrs=
                    (tolower(value[0])=='n')?0:1;  break; /* YearHeaders    */
        case 117: year_totals=
                    (tolower(value[0])=='n')?0:1;  break; /* YearTotals     */
        case 118: use_flags=
                    (tolower(value[0])=='y')?1:0;  break; /* CountryFlags   */
        case 119: use_flags=1; flag_dir=save_opt(value); break; /* FlagDir  */
        case 120: searchcasei=
                    (tolower(value[0])=='n')?0:1;  break; /* SearchCaseI    */
      }
   }
   fclose(fp);
}

/*********************************************/
/* SAVE_OPT - save option from config file   */
/*********************************************/

static char *save_opt(char *str)
{
   char *cp1;

   if ( (cp1=malloc(strlen(str)+1))==NULL) return NULL;

   strcpy(cp1,str);
   return cp1;
}

/*********************************************/
/* CLEAR_MONTH - initalize monthly stuff     */
/*********************************************/

void clear_month()
{
   int i;

   init_counters();                  /* reset monthly counters  */
   del_htabs();                      /* clear hash tables       */
   if (ntop_ctrys!=0 ) for (i=0;i<ntop_ctrys;i++)  top_ctrys[i]=NULL;
}

/*********************************************/
/* INIT_COUNTERS - prep counters for use     */
/*********************************************/

void init_counters()
{
   int i;
   for (i=0;i<TOTAL_RC;i++) response[i].count = 0;
   for (i=0;i<31;i++)  /* monthly totals      */
   {
    tm_xfer[i]=0.0;
    tm_hit[i]=tm_file[i]=tm_site[i]=tm_page[i]=tm_visit[i]=0;
   }
   for (i=0;i<24;i++)  /* hourly totals       */
   {
      th_hit[i]=th_file[i]=th_page[i]=0;
      th_xfer[i]=0.0;
   }
   for (i=0;ctry[i].desc;i++) /* country totals */
   {
      ctry[i].count=0;
      ctry[i].files=0;
      ctry[i].xfer=0;
   }
   t_hit=t_file=t_site=t_url=t_ref=t_agent=t_page=t_visit=t_user=0;
   t_xfer=0.0;
   mh_hit = dt_site = 0;
   f_day=l_day=1;
}

/*********************************************/
/* PRINT_OPTS - print command line options   */
/*********************************************/

void print_opts(char *pname)
{
   int i;

   printf("%s: %s %s\n",h_usage1,pname,h_usage2);
   for (i=0;h_msg[i];i++) printf("%s\n",h_msg[i]);
   exit(1);
}

/*********************************************/
/* PRINT_VERSION                             */
/*********************************************/

void print_version()
{
   char buf[128]="";
   uname(&system_info);

   printf("Webalizer V%s-%s (%s %s %s) %s\n%s\n",
      version,editlvl,
      system_info.sysname,system_info.release,system_info.machine,
      language,copyright);

#ifdef USE_DNS
   strncpy(&buf[strlen(buf)],"DNS/GeoDB ",11);
#endif
#ifdef USE_BZIP
   strncpy(&buf[strlen(buf)],"BZip2 ",7);
#endif
#ifdef USE_GEOIP
   strncpy(&buf[strlen(buf)],"GeoIP ",7);
#endif

   if (debug_mode)
   {
      printf("Mod date: %s  Options: ",moddate);
      if (buf[0]!=0) printf("%s",buf);
      else           printf("none");
      printf("\n");
#if USE_DNS
      printf("Default GeoDB dir : %s\n",GEODB_LOC);
#endif
      printf("Default config dir: %s\n",ETCDIR);
      printf("\n");
   }
   else printf("\n");
   exit(1);
}

/*********************************************/
/* CUR_TIME - return date/time as a string   */
/*********************************************/

char *cur_time()
{
   time_t     now;
   static     char timestamp[48];

   /* get system time */
   now = time(NULL);
   /* convert to timestamp string */
   if (local_time)
      strftime(timestamp,sizeof(timestamp),"%d-%b-%Y %H:%M %Z",
            localtime(&now));
   else
      strftime(timestamp,sizeof(timestamp),"%d-%b-%Y %H:%M GMT",
            gmtime(&now));

   return timestamp;
}

/*********************************************/
/* ISPAGE - determine if an HTML page or not */
/*********************************************/

int ispage(char *str)
{
   NLISTPTR t;
   char *cp1, *cp2;

   if (isinlist(omit_page,str)!=NULL) return 0;

   cp1=cp2=str;
   while (*cp1!='\0') { if (*cp1=='.') cp2=cp1; cp1++; }
   if ((cp2++==str)||(*(--cp1)=='/')) return 1;
   t=page_prefix;
   while(t!=NULL)
   {
      /* Check if a PagePrefix matches */
      if(strncmp(str,t->string,strlen(t->string))==0) return 1;
      t=t->next;
   }
   return (isinlist(page_type,cp2)!=NULL);
}

/*********************************************/
/* ISURLCHAR - checks for valid URL chars    */
/*********************************************/

int isurlchar(unsigned char ch, int flag)
{
   if (isalnum(ch)) return 1;                /* allow letters, numbers...    */
   if (ch > 127)    return 1;                /* allow extended chars...      */
   if (flag)                                 /* and filter some others       */
      return (strchr(":/\\.,' *!-+_@~()[]!",ch)!=NULL);    /* strip cgi vars */
   else
      return (strchr(":/\\.,' *!-+_@~()[]!;?&=",ch)!=NULL); /* keep cgi vars */
}

/*********************************************/
/* CTRY_IDX - create unique # from TLD       */
/*********************************************/

u_int64_t ctry_idx(char *str)
{
   int       i=strlen(str),j=0;
   u_int64_t idx=0;
   char      *cp=str+i;

   for (;i>0;i--) { idx+=((*--cp-'a'+1)<<j); j+=(j==0)?7:5; }
   return idx;
}

/*********************************************/
/* UN_IDX - get TLD from index #             */
/*********************************************/

char *un_idx(u_int64_t idx)
{
   int    i,j;
   char   *cp;
   static char buf[8];

   memset(buf, 0, sizeof(buf));
   if (idx<=0) return buf;
   if ((j=(idx&0x7f))>32) /* only for a1, a2 and o1 */
      { buf[0]=(idx>>7)+'a'; buf[1]=j-32; return buf; }

   for (i=5;i>=0;i--)
      buf[i]=(i==5)?(idx&0x7f)+'a'-1:(j=(idx>>(((5-i)*5)+2))&0x1f)?j+'a'-1:' ';
   cp=buf; while (*cp==' ') { for (i=0;i<6;i++) buf[i]=buf[i+1]; } return buf;
}

/*********************************************/
/* FROM_HEX - convert hex char to decimal    */
/*********************************************/

char from_hex(char c)                           /* convert hex to dec      */
{
   c = (c>='0'&&c<='9')?c-'0':                  /* 0-9?                    */
       (c>='A'&&c<='F')?c-'A'+10:               /* A-F?                    */
       c - 'a' + 10;                            /* lowercase...            */
   return (c<0||c>15)?0:c;                      /* return 0 if bad...      */
}

/*********************************************/
/* UNESCAPE - convert escape seqs to chars   */
/*********************************************/

char *unescape(char *str)
{
   unsigned char *cp1=(unsigned char *)str;     /* force unsigned so we    */
   unsigned char *cp2=cp1;                      /* can do > 127            */

   if (!str) return NULL;                       /* make sure strings valid */

   while (*cp1)
   {
      if (*cp1=='%')                            /* Found an escape?        */
      {
         cp1++;
         if (isxdigit(*cp1))                    /* ensure a hex digit      */
         {
            if (*cp1) *cp2=from_hex(*cp1++)*16; /* convert hex to an ASCII */
            if (*cp1) *cp2+=from_hex(*cp1);     /* (hopefully) character   */
            if ((*cp2<32)||(*cp2==127)) *cp2='_'; /* make '_' if its bad   */
            if (*cp1) { cp2++; cp1++; }
         }
         else *cp2++='%';
      }
      else *cp2++ = *cp1++;                     /* if not, just continue   */
   }
   *cp2=*cp1;                                   /* don't forget terminator */
   return str;                                  /* return the string       */
}

/*********************************************/
/* OURICMP - Case insensitive string compare */
/*********************************************/

int ouricmp(char *str1, char *str2)
{
   while((*str1!=0) &&
    (tolower((unsigned char)*str1)==tolower((unsigned char)*str2)))
    { str1++;str2++; }
   if (*str1==0) return 0; else return 1;
}

/*********************************************/
/* SRCH_STRING - get search strings from ref */
/*********************************************/

void srch_string(char *ptr)
{
   /* ptr should point to unescaped query string */
   char tmpbuf[BUFSIZE];
   char srch[80]="";
   unsigned char *cp1, *cp2, *cps;
   int  sp_flg=0;

   /* Check if search engine referrer or return  */
   if ( (cps=(unsigned char *)isinglist(search_list,log_rec.refer))==NULL)
      return; 

   /* Try to find query variable */
   srch[0]='?'; srch[sizeof(srch)-1] = '\0';
   strncpy(&srch[1],(char *)cps,sizeof(srch)-2);   /* First, try "?..."      */
   if ((cp1=(unsigned char *)strstr(ptr,srch))==NULL)
   {
      srch[0]='&';                                 /* Next, try "&..."       */
      if ((cp1=(unsigned char *)strstr(ptr,srch))==NULL) return;
   }
   cp2=(unsigned char *)tmpbuf;
   while (*cp1!='=' && *cp1!=0) cp1++; if (*cp1!=0) cp1++;
   while (*cp1!='&' && *cp1!=0)
   {
      if (*cp1=='"' || *cp1==',' || *cp1=='?')
          { cp1++; continue; }                         /* skip bad ones..    */
      else
      {
         if (*cp1=='+') *cp1=' ';                      /* change + to space  */
         if (sp_flg && *cp1==' ') { cp1++; continue; } /* compress spaces    */
         if (*cp1==' ') sp_flg=1; else sp_flg=0;       /* (flag spaces here) */
         if (searchcasei)
            *cp2++=tolower(*cp1++);                    /* normal character   */
         else *cp2++=*cp1++;
      }
   }
   *cp2=0; cp2=(unsigned char *)tmpbuf;
   if (tmpbuf[0]=='?') tmpbuf[0]=' ';                  /* format fix ?       */
   while( *cp2!=0 && isspace((unsigned char)*cp2) ) cp2++;     /* skip sps.  */
   if (*cp2==0) return;

   /* any trailing spaces? */
   cp1=cp2+strlen((char *)cp2)-1;
   while (cp1!=cp2) if (isspace((unsigned char)*cp1)) *cp1--='\0'; else break;

   /* strip invalid chars */
   cp1=cp2;
   while (*cp1!=0) { if ((*cp1<32)||(*cp1==127)) *cp1='_'; cp1++; }

   if (put_snode((char *)cp2,(u_int64_t)1,sr_htab))
   {
      if (verbose)
      /* Error adding search string node, skipping .... */
      fprintf(stderr,"%s %s\n", msg_nomem_sc, tmpbuf);
   }
   return;
}

/*********************************************/
/* GET_DOMAIN - Get domain portion of host   */
/*********************************************/

char *get_domain(char *str)
{
   char *cp;
   int  i=group_domains+1;

   if (isipaddr(str)) return NULL;
   cp = str+strlen(str)-1;

   while (cp!=str)
   {
      if (*cp=='.')
         if (!(--i)) return ++cp;
      cp--;
   }
   return cp;
}

/*********************************************/
/* AGENT_MANGLE - Re-format user agent       */
/*********************************************/

void agent_mangle(char *str)
{
   char *cp1, *cp2, *cp3;

   str=cp2=log_rec.agent;
   cp1=strstr(str,"ompatible"); /* check known fakers */
   if (cp1!=NULL)
   {
      while (*cp1!=';'&&*cp1!='\0') cp1++;
      /* kludge for Mozilla/3.01 (compatible;) */
      if (*cp1++==';' && strcmp(cp1,")\""))  /* success! */
      {
         /* Opera can hide as MSIE */
         cp3=strstr(str,"Opera");
         if (cp3!=NULL)
         {
            while (*cp3!='.'&&*cp3!='\0')
            {
               if(*cp3=='/') *cp2++=' ';
               else *cp2++=*cp3;
               cp3++;
            }
            cp1=cp3;
         }
         else
         {
            while (*cp1 == ' ') cp1++; /* eat spaces */
            while (*cp1!='.'&&*cp1!='\0'&&*cp1!=';') *cp2++=*cp1++;
         }
         if (mangle_agent<5)
         {
            while (*cp1!='.'&&*cp1!=';'&&*cp1!='\0') *cp2++=*cp1++;
            if (*cp1!=';'&&*cp1!='\0') { *cp2++=*cp1++; *cp2++=*cp1++; }
         }
         if (mangle_agent<4)
            if (*cp1>='0'&&*cp1<='9') *cp2++=*cp1++;
         if (mangle_agent<3)
            while (*cp1!=';'&&*cp1!='\0'&&*cp1!='('&&*cp1!=' ') *cp2++=*cp1++;
         if (mangle_agent<2)
         {
            /* Level 1 - try to get OS */
            cp1=strstr(cp1,")");
            if (cp1!=NULL)
            {
               *cp2++=' ';
               *cp2++='(';
               while (*cp1!=';'&&*cp1!='('&&cp1!=str) cp1--;
               if (cp1!=str&&*cp1!='\0') cp1++;
               while (*cp1==' '&&*cp1!='\0') cp1++;
               while (*cp1!=')'&&*cp1!='\0') *cp2++=*cp1++;
               *cp2++=')';
            }
         }
         *cp2='\0';
      }
      else
      {
         /* nothing after "compatible", should we mangle? */
         /* not for now */
      }
   }
   else
   {
      cp1=strstr(str,"Opera");  /* Opera flavor         */
      if (cp1!=NULL)
      {
         while (*cp1!='/'&&*cp1!=' '&&*cp1!='\0') *cp2++=*cp1++;
         while (*cp1!='.'&&*cp1!='\0')
         {
            if(*cp1=='/') *cp2++=' ';
            else *cp2++=*cp1;
            cp1++;
         }
         if (mangle_agent<5)
         {
            while (*cp1!='.'&&*cp1!='\0') *cp2++=*cp1++;
            *cp2++=*cp1++;
            *cp2++=*cp1++;
         }
         if (mangle_agent<4)
            if (*cp1>='0'&&*cp1<='9') *cp2++=*cp1++;
         if (mangle_agent<3)
            while (*cp1!=' '&&*cp1!='\0'&&*cp1!='(') *cp2++=*cp1++;
         if (mangle_agent<2)
         {
            cp1=strstr(cp1,"(");
            if (cp1!=NULL)
            {
               cp1++;
               *cp2++=' ';
               *cp2++='(';
               while (*cp1!=';'&&*cp1!=')'&&*cp1!='\0') *cp2++=*cp1++;
               *cp2++=')';
            }
         }
         *cp2='\0';
      }
      else
      { 
         cp1=strstr(str,"Mozilla");  /* Netscape flavor      */
         if (cp1!=NULL)
         {
            while (*cp1!='/'&&*cp1!=' '&&*cp1!='\0') *cp2++=*cp1++;
            if (*cp1==' ') *cp1='/';
            while (*cp1!='.'&&*cp1!='\0') *cp2++=*cp1++;
            if (mangle_agent<5)
            {
               while (*cp1!='.'&&*cp1!='\0') *cp2++=*cp1++;
               *cp2++=*cp1++;
               *cp2++=*cp1++;
            }
            if (mangle_agent<4)
               if (*cp1>='0'&&*cp1<='9') *cp2++=*cp1++;
            if (mangle_agent<3)
               while (*cp1!=' '&&*cp1!='\0'&&*cp1!='(') *cp2++=*cp1++;
            if (mangle_agent<2)
            {
               /* Level 1 - Try to get OS */
               cp1=strstr(cp1,"(");
               if (cp1!=NULL)
               {
                  cp1++;
                  *cp2++=' ';
                  *cp2++='(';
                  while (*cp1!=';'&&*cp1!=')'&&*cp1!='\0') *cp2++=*cp1++;
                  *cp2++=')';
               }
            }
            *cp2='\0';
         }
      }
   }
}

/*********************************************/
/* OUR_GZGETS - enhanced gzgets for log only */
/*********************************************/

char *our_gzgets(void *fp, char *buf, int size)
{
   char *out_cp=buf;      /* point to output */
   while (1)
   {
      if (f_cp>(f_buf+f_end-1))     /* load? */
      {
#ifdef USE_BZIP
         f_end=(gz_log==COMP_BZIP)?
            BZ2_bzread(fp, f_buf, GZ_BUFSIZE):
            gzread(fp, f_buf, GZ_BUFSIZE);
#else
         f_end=gzread(fp, f_buf, GZ_BUFSIZE);
#endif
         if (f_end<=0) return Z_NULL;
         f_cp=f_buf;
      }

      if (--size)                   /* more? */
      {
         *out_cp++ = *f_cp;
         if (*f_cp++ == '\n') { *out_cp='\0'; return buf; }
      }
      else { *out_cp='\0'; return buf; }
   }
}

#ifdef USE_BZIP
/*********************************************/
/* bz2_rewind - our 'rewind' for bz2 files   */
/*********************************************/

int bz2_rewind( void **fp, char *fname, char *mode )
{
   BZ2_bzclose( *fp );
   *fp = BZ2_bzopen( fname, "rb");
   f_cp=f_buf+GZ_BUFSIZE; f_end=0;   /* reset buffer counters */
   memset(f_buf, 0, sizeof(f_buf));
   if (*fp == Z_NULL) return -1;
   else return 0;
}
#endif /* USE_BZIP */

/*********************************************/
/* ISIPADDR - Determine if str is IP address */
/*********************************************/

int isipaddr(char *str)
{
   int  i=1,j=0;
   char *cp;   /* generic ptr  */

   if (strchr(str,':')!=NULL)
   {
      /* Possible IPv6 Address */
      cp=str;
      while (strchr(":.abcdef0123456789",*cp)!=NULL && *cp!='\0')
      {
         if (*cp=='.')   j++;
         if (*cp++==':') i++;
      }

      if (*cp!='\0') return -1;                   /* bad hostname (has ':') */
      if (i>1 && j) return 2;                     /* IPv4/IPv6    */
      return 3;                                   /* IPv6         */
   }
   else
   {
      /* Not an IPv6 address, check for IPv4 */
      cp=str;
      while (strchr(".0123456789",*cp)!=NULL && *cp!='\0')
      {
         if (*cp++=='.') i++;
      }
      if (*cp!='\0') return 0;                    /* hostname     */
      if (i!=4) return -1;                        /* bad hostname */
      return 1;                                   /* IPv4         */
   }
}

/*****************************************************************/
/*                                                               */
/* JDATE  - Julian date calculator                               */
/*                                                               */
/* Calculates the number of days since Jan 1, 0000.              */
/*                                                               */
/* Originally written by Bradford L. Barrett (03/17/1988)        */
/* Returns an unsigned long value representing the number of     */
/* days since January 1, 0000.                                   */
/*                                                               */
/* Note: Due to the changes made by Pope Gregory XIII in the     */
/*       16th Centyry (Feb 24, 1582), dates before 1583 will     */
/*       not return a truely accurate number (will be at least   */
/*       10 days off).  Somehow, I don't think this will         */
/*       present much of a problem for most situations :)        */
/*                                                               */
/* Usage: days = jdate(day, month, year)                         */
/*                                                               */
/* The number returned is adjusted by 5 to facilitate day of     */
/* week calculations.  The mod of the returned value gives the   */
/* day of the week the date is.  (ie: dow = days % 7 ) where     */
/* dow will return 0=Sunday, 1=Monday, 2=Tuesday, etc...         */
/*                                                               */
/*****************************************************************/

u_int64_t jdate( int day, int month, int year )
{
   u_int64_t days;                      /* value returned */
   int mtable[] = {0,31,59,90,120,151,181,212,243,273,304,334};

   /* First, calculate base number including leap and Centenial year stuff */

   days=(((u_int64_t)year*365)+day+mtable[month-1]+
           ((year+4)/4) - ((year/100)-(year/400)));

   /* now adjust for leap year before March 1st */

   if ((year % 4 == 0) && !((year % 100 == 0) &&
       (year % 400 != 0)) && (month < 3))
   --days;

   /* done, return with calculated value */

   return(days+5);
}
