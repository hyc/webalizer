#ifndef _HASHTAB_H
#define _HASHTAB_H

typedef struct hnode *HNODEPTR;            /* site node (host) pointer     */
typedef struct unode *UNODEPTR;            /* url node pointer             */
typedef struct rnode *RNODEPTR;            /* referrer node                */
typedef struct anode *ANODEPTR;            /* user agent node pointer      */
typedef struct snode *SNODEPTR;            /* Search string node pointer   */
typedef struct inode *INODEPTR;            /* user (ident) node pointer    */
#ifdef USE_DNS
typedef struct dnode *DNODEPTR;            /* DNS hash table node struct   */
#endif

/* Object flags */
#define OBJ_REG  0                         /* Regular object               */
#define OBJ_HIDE 1                         /* Hidden object                */
#define OBJ_GRP  2                         /* Grouped object               */

#ifdef USE_DNS
struct dnode {  char *string;              /* DNS node hash table struct   */
              struct sockaddr_storage  addr;
                 int addrlen;
              struct dnode    *llist;
              struct dnode    *next; };
#endif

struct hnode {  char *string;              /* host hash table structure    */
                 int flag;
           u_int64_t count;
           u_int64_t files;
           u_int64_t visit;                /* visit information            */
           u_int64_t tstamp;
                char *lasturl;
              double xfer;
              struct hnode *next; };

struct unode {  char *string;              /* url hash table structure     */
                 int flag;                 /* Object type (REG, HIDE, GRP) */
           u_int64_t count;                /* requests counter             */
           u_int64_t files;                /* files counter                */
           u_int64_t entry;                /* entry page counter           */
           u_int64_t exit;                 /* exit page counter            */
              double xfer;                 /* xfer size in bytes           */
              struct unode *next; };       /* pointer to next node         */

struct rnode {  char *string;              /* referrer hash table struct   */
                 int flag;
           u_int64_t count;
              struct rnode *next; };

struct anode {  char *string;
                 int flag;
           u_int64_t count;
              struct anode *next; };

struct snode {  char *string;                 /* search string struct      */
           u_int64_t count;
              struct snode *next; };

struct inode {  char *string;                 /* host hash table struct    */
                 int flag;
           u_int64_t count;
           u_int64_t files;
           u_int64_t visit;
           u_int64_t tstamp;
              double xfer;
              struct inode *next; };

extern HNODEPTR sm_htab[MAXHASH];             /* hash tables               */
extern HNODEPTR sd_htab[MAXHASH];
extern UNODEPTR um_htab[MAXHASH];             /* for hits, sites,          */
extern RNODEPTR rm_htab[MAXHASH];             /* referrers and agents...   */
extern ANODEPTR am_htab[MAXHASH];
extern SNODEPTR sr_htab[MAXHASH];             /* search string table       */
extern INODEPTR im_htab[MAXHASH];             /* ident table (username)    */
#ifdef USE_DNS
extern DNODEPTR host_table[MAXHASH];          /* DNS resolver table        */
#endif

extern int    put_hnode(char *, int, u_int64_t, u_int64_t, double,
                        u_int64_t *, u_int64_t, u_int64_t, char *, HNODEPTR *);
extern int    put_unode(char *, int, u_int64_t, double, u_int64_t *,
                        u_int64_t, u_int64_t, UNODEPTR *);
extern int    put_inode(char *, int, u_int64_t, u_int64_t, double,
                        u_int64_t *, u_int64_t, u_int64_t, INODEPTR *);
extern int    put_rnode(char *, int, u_int64_t, u_int64_t *, RNODEPTR *);
extern int    put_anode(char *, int, u_int64_t, u_int64_t *, ANODEPTR *);
extern int    put_snode(char *, u_int64_t, SNODEPTR *);

#ifdef USE_DNS
extern int    put_dnode(char *, void *, int, DNODEPTR *);
extern void   del_dlist(DNODEPTR *);
#endif

extern void   del_htabs();                    /* delete hash tables        */
extern void   del_hlist(HNODEPTR *);          /* delete host htab          */
extern void   del_ulist(UNODEPTR *);          /* delete url htab           */
extern void   del_rlist(RNODEPTR *);          /* delete referrer htab      */
extern void   del_alist(ANODEPTR *);          /* delete host htab          */
extern void   del_slist(SNODEPTR *);          /* delete host htab          */
extern void   del_ilist(INODEPTR *);          /* delete host htab          */

extern void      month_update_exit(u_int64_t);
extern u_int64_t tot_visit(HNODEPTR *);
extern char     *find_url(char *);

#endif  /* _HASHTAB_H */
