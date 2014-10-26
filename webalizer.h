#ifndef _WEBALIZER_H
#define _WEBALIZER_H

#define PCENT(val,max) ((val)?((double)val/(double)max)*100.0 : 0.0)
#define IDX_2C(c1,c2)       (((c1-'a'+1)<<7)+(c2-'a'+1) )
#define IDX_3C(c1,c2,c3)    (((c1-'a'+1)<<12)+((c2-'a'+1)<<7)+(c3-'a'+1) )
#define IDX_4C(c1,c2,c3,c4) (((c1-'a'+1)<<17)+((c2-'a'+1)<<12)+((c3-'a'+1)<<7)+(c4-'a'+1) )
#define IDX_5C(c1,c2,c3,c4,c5) (((c1-'a'+1)<<22)+((c2-'a'+1)<<17)+((c3-'a'+1)<<12)+((c4-'a'+1)<<7)+(c5-'a'+1) )
#define IDX_6C(c1,c2,c3,c4,c5,c6) (((c1-'a'+1)<<27)+((c2-'a'+1)<<22)+((c3-'a'+1)<<17)+((c4-'a'+1)<<12)+((c5-'a'+1)<<7)+(c6-'a'+1) )

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#define MAXHASH  4096                  /* Size of our hash tables          */
#define BUFSIZE  4096                  /* Max buffer size for log record   */
#define MAXHOST  256                   /* Max hostname buffer size         */
#define MAXURL   4096                  /* Max HTTP request/URL field size  */
#define MAXURLH  512                   /* Max URL field size in htab       */
#define MAXREF   1024                  /* Max referrer field size          */
#define MAXREFH  256                   /* Max referrer field size in htab  */
#define MAXAGENT 128                   /* Max user agent field size        */
#define MAXCTRY  48                    /* Max country name size            */
#define MAXSRCH  256                   /* Max size of search string buffer */
#define MAXSRCHH 128                   /* Max size of search str in htab   */
#define MAXIDENT 64                    /* Max size of ident string (user)  */
#define MAXKWORD 32                    /* Max size of config keyword       */
#define MAXKVAL  132                   /* Max size of config value         */
#define HISTSIZE 120                   /* Size of history in months        */
#define GRAPHMAX 72                    /* Max months in index graph        */

#define SLOP_VAL 3600                  /* out of sequence slop (seconds)   */

/* Log types */
#define LOG_CLF   0                    /* CLF/combined log type            */
#define LOG_FTP   1                    /* wu-ftpd xferlog type             */
#define LOG_SQUID 2                    /* squid proxy log                  */
#define LOG_W3C   3                    /* W3C extended log format          */

/* compression */
#define COMP_NONE 0
#define COMP_GZIP 1
#define COMP_BZIP 2

/* Response code defines as per draft ietf HTTP/1.1 rev 6 */
#define RC_CONTINUE           100
#define RC_SWITCHPROTO        101
#define RC_OK                 200
#define RC_CREATED            201
#define RC_ACCEPTED           202
#define RC_NONAUTHINFO        203
#define RC_NOCONTENT          204
#define RC_RESETCONTENT       205
#define RC_PARTIALCONTENT     206
#define RC_MULTIPLECHOICES    300
#define RC_MOVEDPERM          301
#define RC_MOVEDTEMP          302
#define RC_SEEOTHER           303
#define RC_NOMOD              304
#define RC_USEPROXY           305
#define RC_MOVEDTEMPORARILY   307
#define RC_BAD                400
#define RC_UNAUTH             401
#define RC_PAYMENTREQ         402
#define RC_FORBIDDEN          403
#define RC_NOTFOUND           404
#define RC_METHODNOTALLOWED   405
#define RC_NOTACCEPTABLE      406
#define RC_PROXYAUTHREQ       407
#define RC_TIMEOUT            408
#define RC_CONFLICT           409
#define RC_GONE               410
#define RC_LENGTHREQ          411
#define RC_PREFAILED          412
#define RC_REQENTTOOLARGE     413
#define RC_REQURITOOLARGE     414
#define RC_UNSUPMEDIATYPE     415
#define RC_RNGNOTSATISFIABLE  416
#define RC_EXPECTATIONFAILED  417
#define RC_SERVERERR          500
#define RC_NOTIMPLEMENTED     501
#define RC_BADGATEWAY         502
#define RC_UNAVAIL            503
#define RC_GATEWAYTIMEOUT     504
#define RC_BADHTTPVER         505

/* Index defines for RC codes */
#define IDX_UNDEFINED          0
#define IDX_CONTINUE           1
#define IDX_SWITCHPROTO        2
#define IDX_OK                 3
#define IDX_CREATED            4 
#define IDX_ACCEPTED           5 
#define IDX_NONAUTHINFO        6 
#define IDX_NOCONTENT          7  
#define IDX_RESETCONTENT       8 
#define IDX_PARTIALCONTENT     9 
#define IDX_MULTIPLECHOICES    10 
#define IDX_MOVEDPERM          11 
#define IDX_MOVEDTEMP          12 
#define IDX_SEEOTHER           13 
#define IDX_NOMOD              14 
#define IDX_USEPROXY           15 
#define IDX_MOVEDTEMPORARILY   16
#define IDX_BAD                17 
#define IDX_UNAUTH             18 
#define IDX_PAYMENTREQ         19 
#define IDX_FORBIDDEN          20 
#define IDX_NOTFOUND           21 
#define IDX_METHODNOTALLOWED   22 
#define IDX_NOTACCEPTABLE      23 
#define IDX_PROXYAUTHREQ       24 
#define IDX_TIMEOUT            25 
#define IDX_CONFLICT           26 
#define IDX_GONE               27 
#define IDX_LENGTHREQ          28 
#define IDX_PREFAILED          29 
#define IDX_REQENTTOOLARGE     30 
#define IDX_REQURITOOLARGE     31 
#define IDX_UNSUPMEDIATYPE     32
#define IDX_RNGNOTSATISFIABLE  33
#define IDX_EXPECTATIONFAILED  34 
#define IDX_SERVERERR          35 
#define IDX_NOTIMPLEMENTED     36 
#define IDX_BADGATEWAY         37 
#define IDX_UNAVAIL            38 
#define IDX_GATEWAYTIMEOUT     39 
#define IDX_BADHTTPVER         40 
#define TOTAL_RC               41

#ifdef USE_DNS
#include <netinet/in.h>       /* needed for in_addr structure definition   */
#ifndef INADDR_NONE
#define INADDR_NONE 0xFFFFFFFF
#endif  /* INADDR_NONE */
#endif

/* Response code structure */
struct response_code {     char    *desc;         /* code description     */
                      u_int64_t    count; };      /* hit counter          */

/* Country code structure */
struct	country_code {u_int64_t idx;              /* TLD index number     */
                           char *desc;            /* TLD description      */
                      u_int64_t count;            /* hit counter          */
                      u_int64_t files;            /* file counter         */
                         double xfer; };          /* xfer amt counter     */

typedef struct country_code *CLISTPTR;

/* log record structure */
struct  log_struct  {  char   hostname[MAXHOST];  /* hostname             */
                       char   datetime[29];       /* raw timestamp        */
                       char   url[MAXURL];        /* raw request field    */
                        int   resp_code;          /* response code        */
                  u_int64_t   xfer_size;          /* xfer size in bytes   */
                       char   refer[MAXREF];      /* referrer             */
                       char   agent[MAXAGENT];    /* user agent (browser) */
                       char   srchstr[MAXSRCH];   /* search string        */
                       char   ident[MAXIDENT]; }; /* ident string (user)  */

extern struct log_struct log_rec;

extern char    *version     ;                 /* program version          */
extern char    *editlvl     ;                 /* edit level               */
extern char    *moddate     ;                 /* modification date        */
extern char    *copyright   ;

extern int     verbose      ;                 /* 2=verbose,1=err, 0=none  */ 
extern int     debug_mode   ;                 /* debug mode flag          */
extern int     time_me      ;                 /* timing display flag      */
extern int     local_time   ;                 /* 1=localtime 0=GMT (UTC)  */
extern int     hist_gap     ;                 /* hist error, save backup  */
extern int     ignore_hist  ;                 /* history flag (1=skip)    */
extern int     ignore_state ;                 /* state fiag (1=skip)      */
extern int     hourly_graph ;                 /* hourly graph display     */
extern int     hourly_stats ;                 /* hourly stats table       */
extern int     daily_graph  ;                 /* daily graph display      */
extern int     daily_stats  ;                 /* daily stats table        */
extern int     ctry_graph   ;                 /* country graph display    */
extern int     shade_groups ;                 /* Group shading 0=no 1=yes */
extern int     hlite_groups ;                 /* Group hlite 0=no 1=yes   */
extern int     mangle_agent ;                 /* mangle user agents       */
extern int     incremental  ;                 /* incremental mode 1=yes   */
extern int     use_https    ;                 /* use 'https://' on URLs   */
extern int     htaccess     ;                 /* create .htaccess? (0=no) */
extern int     visit_timeout;                 /* visit timeout (30 min)   */
extern int     graph_legend ;                 /* graph legend (1=yes)     */
extern int     graph_lines  ;                 /* graph lines (0=none)     */
extern int     fold_seq_err ;                 /* fold seq err (0=no)      */
extern int     log_type     ;                 /* (0=clf, 1=ftp, 2=squid)  */
extern int     group_domains;                 /* Group domains 0=none     */
extern int     hide_sites   ;                 /* Hide ind. sites (0=no)   */
extern int     graph_mths   ;                 /* # months in index graph  */
extern int     index_mths   ;                 /* # months in index table  */
extern int     year_hdrs    ;                 /* Show year headers (0=no) */
extern int     year_totals  ;                 /* Show year totals (0=no)  */
extern int     use_flags    ;                 /* Show flags in ctry table */
extern char    *flag_dir    ;                 /* flag directory           */
extern char    *hname       ;                 /* hostname for reports     */
extern char    *state_fname ;                 /* run state file name      */
extern char    *hist_fname  ;                 /* name of history file     */
extern char    *html_ext    ;                 /* HTML file prefix         */
extern char    *dump_ext    ;                 /* Dump file prefix         */
extern char    *conf_fname  ;                 /* name of config file      */
extern char    *log_fname   ;                 /* log file pointer         */
extern char    *out_dir     ;                 /* output directory         */
extern char    *blank_str   ;                 /* blank string             */
extern char    *dns_cache   ;                 /* DNS cache file name      */
extern int     geodb        ;                 /* Use GeoDB flag (0=no)    */
extern int     dns_children ;                 /* # of DNS children        */
extern int     cache_ips    ;                 /* Cache IP addrs (0=no)    */
extern int     cache_ttl    ;                 /* Cache entry TTL (days)   */
extern int     link_referrer;                 /* link referrer (0=no)     */
extern int     trimsquid    ;                 /* trim squid URLs (0=none) */
extern int     searchcasei  ;                 /* case insensitive search  */

extern int     ntop_sites   ;                 /* top n sites to display   */
extern int     ntop_sitesK  ;                 /* top n sites (by kbytes)  */
extern int     ntop_urls    ;                 /* top n url's to display   */
extern int     ntop_urlsK   ;                 /* top n url's (by kbytes)  */
extern int     ntop_entry   ;                 /* top n entry url's        */
extern int     ntop_exit    ;                 /* top n exit url's         */
extern int     ntop_refs    ;                 /* top n referrers ""       */
extern int     ntop_agents  ;                 /* top n user agents ""     */
extern int     ntop_ctrys   ;                 /* top n countries   ""     */
extern int     ntop_search  ;                 /* top n search strings     */
extern int     ntop_users   ;                 /* top n users to display   */

extern int     all_sites    ;                 /* List All sites (0=no)    */
extern int     all_urls     ;                 /* List All URLs  (0=no)    */
extern int     all_refs     ;                 /* List All Referrers       */
extern int     all_agents   ;                 /* List All User Agents     */
extern int     all_search   ;                 /* List All Search Strings  */
extern int     all_users    ;                 /* List All Usernames       */

extern int     dump_sites   ;                 /* Dump tab delimited sites */
extern int     dump_urls    ;                 /* URLs                     */
extern int     dump_refs    ;                 /* Referrers                */
extern int     dump_agents  ;                 /* User Agents              */
extern int     dump_users   ;                 /* Usernames                */
extern int     dump_search  ;                 /* Search strings           */
extern int     dump_header  ;                 /* Dump header as first rec */
extern char    *dump_path   ;                 /* Path for dump files      */

extern u_int64_t cur_tstamp;                  /* Current timestamp        */
extern u_int64_t epoch;                       /* used for timestamp adj.  */
extern int       check_dup;                   /* check for dups flag      */

extern int       cur_year,cur_month,          /* year/month/day/hour      */
                 cur_day, cur_hour,           /* tracking variables       */
                 cur_min, cur_sec;

extern double    t_xfer;                      /* monthly total xfer value */
extern u_int64_t t_hit, t_file, t_site,       /* monthly total vars       */
                 t_url, t_ref,  t_agent,
                 t_page,t_visit,t_user;

extern double    tm_xfer[31];                 /* daily transfer totals    */

extern u_int64_t tm_hit[31], tm_file[31],     /* daily total arrays       */
                 tm_site[31],tm_page[31],
                 tm_visit[31];

extern u_int64_t dt_site;                     /* daily 'sites' total      */

extern u_int64_t ht_hit,mh_hit;               /* hourly hits totals       */

extern u_int64_t th_hit[24], th_file[24],     /* hourly total arrays      */
                 th_page[24];

extern double    th_xfer[24];                 /* hourly xfer array        */

extern int       f_day,l_day;                 /* first/last day vars      */
extern int       gz_log;                      /* flag for zipped log      */

extern CLISTPTR  *top_ctrys;                  /* Top countries table      */

extern char    hit_color[];                   /* graph hit color          */
extern char    file_color[];                  /* graph file color         */
extern char    site_color[];                  /* graph site color         */
extern char    kbyte_color[];                 /* graph kbyte color        */
extern char    page_color[];                  /* graph page color         */
extern char    visit_color[];                 /* graph visit color        */
extern char    misc_color[];                  /* graph misc color         */
extern char    pie_color1[];                  /* pie additionnal color 1  */
extern char    pie_color2[];                  /* pie additionnal color 2  */
extern char    pie_color3[];                  /* pie additionnal color 3  */
extern char    pie_color4[];                  /* pie additionnal color 4  */

/* define our externally visable functions */

extern char      *cur_time();
extern u_int64_t ctry_idx(char *);
extern char      *un_idx(u_int64_t);
extern void      init_counters();
extern int       ispage(char *);
extern u_int64_t jdate(int,int,int);
extern char      from_hex(char);
extern int       isipaddr(char *);

#endif  /* _WEBALIZER_H */
