#ifndef _LINKLIST_H
#define _LINKLIST_H

struct nlist {  char string[MAXKVAL];     /* list struct for HIDE items   */
              struct nlist *next; };
typedef struct nlist *NLISTPTR;

struct glist {  char string[MAXKVAL];     /* list struct for GROUP items  */
                char name[MAXKVAL];
              struct glist *next; };
typedef struct glist *GLISTPTR;

extern GLISTPTR group_sites   ;               /* "group" lists            */
extern GLISTPTR group_urls    ;
extern GLISTPTR group_refs    ;
extern GLISTPTR group_agents  ;
extern GLISTPTR group_users   ;
extern NLISTPTR hidden_sites  ;               /* "hidden" lists           */
extern NLISTPTR hidden_urls   ;       
extern NLISTPTR hidden_refs   ;       
extern NLISTPTR hidden_agents ;       
extern NLISTPTR hidden_users  ;       
extern NLISTPTR ignored_sites ;               /* "Ignored" lists          */
extern NLISTPTR ignored_urls  ;       
extern NLISTPTR ignored_refs  ;       
extern NLISTPTR ignored_agents;       
extern NLISTPTR ignored_users ;       
extern NLISTPTR include_sites ;               /* "Include" lists          */
extern NLISTPTR include_urls  ;       
extern NLISTPTR include_refs  ;       
extern NLISTPTR include_agents;       
extern NLISTPTR include_users ;       
extern NLISTPTR index_alias   ;               /* index. aliases            */
extern NLISTPTR html_pre      ;               /* before anything else :)   */
extern NLISTPTR html_head     ;               /* top HTML code             */
extern NLISTPTR html_body     ;               /* body HTML code            */
extern NLISTPTR html_post     ;               /* middle HTML code          */
extern NLISTPTR html_tail     ;               /* tail HTML code            */
extern NLISTPTR html_end      ;               /* after everything else     */
extern NLISTPTR page_type     ;               /* page view types           */
extern NLISTPTR omit_page     ;               /* pages not counted         */
extern NLISTPTR page_prefix   ;               /* page view prefixes        */
extern GLISTPTR search_list   ;               /* Search engine list        */

extern char     *isinlist(NLISTPTR, char *);        /* scan list for str   */
extern char     *isinglist(GLISTPTR, char *);       /* scan glist for str  */
extern int      add_nlist(char *, NLISTPTR *);      /* add list item       */
extern int      add_glist(char *, GLISTPTR *);      /* add group list item */

#endif  /* _LINKLIST_H */
