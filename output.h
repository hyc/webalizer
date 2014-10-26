#ifndef _OUTPUT_H
#define _OUTPUT_H

extern int   write_main_index();                    /* produce main HTML   */
extern int   write_month_html();                    /* monthy HTML page    */
extern FILE  *open_out_file(char *);                /* open output file    */
#ifdef USE_DNS
extern char  *geodb_get_cc(DB *, char *, char *);
extern DB    *geo_db;
#endif

#endif  /* _OUTPUT_H */
