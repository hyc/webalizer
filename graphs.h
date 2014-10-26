#ifndef _GRAPHS_H
#define _GRAPHS_H

extern int  month_graph6(char *, char *, int, int, u_int64_t *,
             u_int64_t *, u_int64_t *, double *, u_int64_t *, u_int64_t *);
extern int  year_graph6x(char *, char *, struct hist_rec *);
extern int  day_graph3(char *, char *, u_int64_t *, u_int64_t *, u_int64_t *);
extern int  pie_chart(char *, char *, u_int64_t, u_int64_t *, char **);

#endif  /* _GRAPHS_H */
