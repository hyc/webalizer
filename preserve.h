#ifndef _PRESERVE_H
#define _PRESERVE_H

#define mth_idx(m,y) (m+((y-1970)*12))

extern void    get_history();                 /* load history file        */
extern void    put_history();                 /* save history file        */
extern void    populate_history(int, int);    /* populate history w/dates */
extern void    update_history();              /* update w/current totals  */
extern int     save_state();                  /* save run state           */
extern int     restore_state();               /* restore run state        */

/* history record struct */
struct hist_rec {       int   year;           /* year                     */
                        int   month;          /* month                    */
                        int   fday;           /* first day w/data         */
                        int   lday;           /* last day w/data          */
                  u_int64_t   hit;            /* hits for month           */
                  u_int64_t   files;          /* files for month          */
                  u_int64_t   site;           /* sites for month          */
                  u_int64_t   page;           /* pages for month          */
                  u_int64_t   visit;          /* visits for month         */
                     double   xfer;           /* xfer amt for month       */
                };

extern struct hist_rec hist[HISTSIZE];        /* declare our hist array   */

#endif  /* _PRESERVE_H */
