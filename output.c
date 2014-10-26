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
#include <unistd.h>                           /* normal stuff             */
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#ifdef USE_DNS
#include <db.h>
#endif

/* ensure sys/types */
#ifndef _SYS_TYPES_H
#include <sys/types.h>
#endif

/* need socket header? */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

/* some systems need this */
#ifdef HAVE_MATH_H
#include <math.h>
#endif

#ifdef USE_GEOIP
#include <GeoIP.h>
#endif

#include "webalizer.h"                        /* main header              */
#include "lang.h"
#include "hashtab.h"
#include "preserve.h"
#include "linklist.h"
#include "graphs.h"
#include "output.h"

/* internal function prototypes */
void    write_html_head(char *, FILE *);            /* head of html page   */
void    write_html_tail(FILE *);                    /* tail of html page   */
void    month_links();                              /* Page links          */
void    month_total_table();                        /* monthly total table */
void    daily_total_table();                        /* daily total table   */
void    hourly_total_table();                       /* hourly total table  */
void    top_sites_table(int);                       /* top n sites table   */
void    top_urls_table(int);                        /* top n URLs table    */
void    top_entry_table(int);                       /* top n entry/exits   */
void    top_refs_table();                           /* top n referrers ""  */
void    top_agents_table();                         /* top n u-agents  ""  */
void    top_ctry_table();                           /* top n countries ""  */
void    top_search_table();                         /* top n search strs   */
void    top_users_table();                          /* top n ident table   */
u_int64_t load_url_array(  UNODEPTR *);             /* load URL array      */
u_int64_t load_site_array( HNODEPTR *);             /* load Site array     */
u_int64_t load_ref_array(  RNODEPTR *);             /* load Refs array     */
u_int64_t load_agent_array(ANODEPTR *);             /* load Agents array   */
u_int64_t load_srch_array( SNODEPTR *);             /* load srch str array */
u_int64_t load_ident_array(INODEPTR *);             /* load ident array    */
int	qs_url_cmph( const void*, const void*);     /* compare by hits     */
int	qs_url_cmpk( const void*, const void*);     /* compare by kbytes   */
int	qs_url_cmpn( const void*, const void*);     /* compare by entrys   */
int	qs_url_cmpx( const void*, const void*);     /* compare by exits    */
int	qs_site_cmph(const void*, const void*);     /* compare by hits     */
int	qs_site_cmpk(const void*, const void*);     /* compare by kbytes   */
int	qs_ref_cmph( const void*, const void*);     /* compare by hits     */
int     qs_agnt_cmph(const void*, const void*);     /* compare by hits     */
int     qs_srch_cmph(const void*, const void*);     /* compare by hits     */
int     qs_ident_cmph(const void*, const void*);    /* compare by hits     */
int     qs_ident_cmpk(const void*, const void*);    /* compare by kbytes   */

int     all_sites_page(u_int64_t, u_int64_t);       /* output site page    */
int     all_urls_page(u_int64_t, u_int64_t);        /* output urls page    */
int     all_refs_page(u_int64_t, u_int64_t);        /* output refs page    */
int     all_agents_page(u_int64_t, u_int64_t);      /* output agents page  */
int     all_search_page(u_int64_t, u_int64_t);      /* output search page  */
int     all_users_page(u_int64_t, u_int64_t);       /* output ident page   */
void    dump_all_sites();                           /* dump sites tab file */
void    dump_all_urls();                            /* dump urls tab file  */
void    dump_all_refs();                            /* dump refs tab file  */
void    dump_all_agents();                          /* dump agents file    */
void    dump_all_users();                           /* dump usernames file */
void    dump_all_search();                          /* dump search file    */

/* define some colors for HTML */
#define WHITE          "#FFFFFF"
#define BLACK          "#000000"
#define RED            "#FF0000"
#define ORANGE         "#FF8000"
#define LTBLUE         "#0080FF"
#define BLUE           "#0000FF"
#define GREEN          "#00FF00"
#define DKGREEN        "#008040"
#define GREY           "#C0C0C0"
#define LTGREY         "#E8E8E8"
#define YELLOW         "#FFFF00"
#define PURPLE         "#FF00FF"
#define CYAN           "#00E0FF"
#define GRPCOLOR       "#D0D0E0"

/* configurable html colors */
#define HITCOLOR       hit_color
#define FILECOLOR      file_color
#define SITECOLOR      site_color
#define KBYTECOLOR     kbyte_color
#define PAGECOLOR      page_color
#define VISITCOLOR     visit_color
#define MISCCOLOR      misc_color

/* sort arrays */
UNODEPTR *u_array      = NULL;                /* Sort array for URLs      */
HNODEPTR *h_array      = NULL;                /* hostnames (sites)        */
RNODEPTR *r_array      = NULL;                /* referrers                */
ANODEPTR *a_array      = NULL;                /* user agents              */
SNODEPTR *s_array      = NULL;                /* search strings           */
INODEPTR *i_array      = NULL;                /* ident strings (username) */
u_int64_t a_ctr        = 0;                   /* counter for sort array   */

FILE     *out_fp;

/*********************************************/
/* WRITE_HTML_HEAD - output top of HTML page */
/*********************************************/

void write_html_head(char *period, FILE *out_fp)
{
   NLISTPTR lptr;                          /* used for HTMLhead processing */

   /* HTMLPre code goes before all else    */
   lptr = html_pre;
   if (lptr==NULL)
   {
      /* Default 'DOCTYPE' header record if none specified */
      fprintf(out_fp,
      "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\n");
   }
   else
   {
      while (lptr!=NULL)
      {
         fprintf(out_fp,"%s\n",lptr->string);
         lptr=lptr->next;
      }
   }
   /* Standard header comments */
   fprintf(out_fp,"<!-- Generated by The Webalizer  Ver. %s-%s -->\n",
      version,editlvl);
   fprintf(out_fp,"<!--                                          -->\n");
   fprintf(out_fp,"<!-- Copyright 1997-2013  Bradford L. Barrett -->\n");
   fprintf(out_fp,"<!--                                          -->\n");
   fprintf(out_fp,"<!-- Distributed under the GNU GPL  Version 2 -->\n");
   fprintf(out_fp,"<!--        Full text may be found at:        -->\n");
   fprintf(out_fp,"<!--         http://www.webalizer.org         -->\n");
   fprintf(out_fp,"<!--                                          -->\n");
   fprintf(out_fp,"<!--  Give the power back to the programmers  -->\n");
   fprintf(out_fp,"<!--   Support the Free Software Foundation   -->\n");
   fprintf(out_fp,"<!--           (http://www.fsf.org)           -->\n");
   fprintf(out_fp,"<!--                                          -->\n");
   fprintf(out_fp,"<!-- *** Generated: %s *** -->\n\n",cur_time());

   fprintf(out_fp,"<HTML lang=\"%s\">\n<HEAD>\n",langcode);
   fprintf(out_fp," <TITLE>%s %s - %s</TITLE>\n",
                  msg_title, hname, (period)?period:msg_main_per);
   lptr=html_head;
   while (lptr!=NULL)
   {
      fprintf(out_fp,"%s\n",lptr->string);
      lptr=lptr->next;
   }
   fprintf(out_fp,"</HEAD>\n\n");

   lptr = html_body;
   if (lptr==NULL)
      fprintf(out_fp,"<BODY BGCOLOR=\"%s\" TEXT=\"%s\" "   \
              "LINK=\"%s\" VLINK=\"%s\">\n",
              LTGREY, BLACK, BLUE, RED);
   else
   {
      while (lptr!=NULL)
      {
         fprintf(out_fp,"%s\n",lptr->string);
         lptr=lptr->next;
      }
   }
   fprintf(out_fp,"<H2>%s %s</H2>\n",msg_title, hname);
   if (period)
      fprintf(out_fp,"<SMALL><STRONG>\n%s: %s<BR>\n",msg_hhdr_sp,period);
   else
      fprintf(out_fp,"<SMALL><STRONG>\n%s<BR>\n",msg_main_per);
   fprintf(out_fp,"%s %s<BR>\n</STRONG></SMALL>\n",msg_hhdr_gt,cur_time());
   lptr=html_post;
   while (lptr!=NULL)
   {
      fprintf(out_fp,"%s\n",lptr->string);
      lptr=lptr->next;
   }
   fprintf(out_fp,"<CENTER>\n<HR>\n<P>\n");
}

/*********************************************/
/* WRITE_HTML_TAIL - output HTML page tail   */
/*********************************************/

void write_html_tail(FILE *out_fp)
{
   NLISTPTR lptr;

   fprintf(out_fp,"</CENTER>\n");
   fprintf(out_fp,"<P>\n<HR>\n");
   fprintf(out_fp,"<TABLE WIDTH=\"100%%\" CELLPADDING=0 " \
                  "CELLSPACING=0 BORDER=0>\n");
   fprintf(out_fp,"<TR>\n");
   fprintf(out_fp,"<TD ALIGN=left VALIGN=top>\n");
   fprintf(out_fp,"<SMALL>Generated by\n");
   fprintf(out_fp,"<A HREF=\"http://www.webalizer.org/\">");
   fprintf(out_fp,"<STRONG>Webalizer Version %s</STRONG></A>\n",version);
   fprintf(out_fp,"</SMALL>\n</TD>\n");
   lptr=html_tail;
   if (lptr)
   {
      fprintf(out_fp,"<TD ALIGN=\"right\" VALIGN=\"top\">\n");
      while (lptr!=NULL)
      {
         fprintf(out_fp,"%s\n",lptr->string);
         lptr=lptr->next;
      }
      fprintf(out_fp,"</TD>\n");
   }
   fprintf(out_fp,"</TR>\n</TABLE>\n");

   /* wind up, this is the end of the file */
   fprintf(out_fp,"\n<!-- Webalizer Version %s-%s (Mod: %s) -->\n",
           version,editlvl,moddate);
   lptr = html_end;
   if (lptr)
   {
      while (lptr!=NULL)
      {
         fprintf(out_fp,"%s\n",lptr->string);
         lptr=lptr->next;
      }
   }
   else fprintf(out_fp,"\n</BODY>\n</HTML>\n");
}

/*********************************************/
/* WRITE_MONTH_HTML - does what it says...   */
/*********************************************/

int write_month_html()
{
   char html_fname[256];           /* filename storage areas...       */
   char png1_fname[32];
   char png2_fname[32];

   char buffer[BUFSIZE];           /* scratch buffer                  */
   char dtitle[256];
   char htitle[256];

   if (verbose>1)
      printf("%s %s %d\n",msg_gen_rpt, l_month[cur_month-1], cur_year); 

   /* fill in filenames */
   snprintf(html_fname,sizeof(html_fname),"usage_%04d%02d.%s",
            cur_year,cur_month,html_ext);
   sprintf(png1_fname,"daily_usage_%04d%02d.png",cur_year,cur_month);
   sprintf(png2_fname,"hourly_usage_%04d%02d.png",cur_year,cur_month);

   /* create PNG images for web page */
   if (daily_graph)
   {
      snprintf(dtitle,sizeof(dtitle),"%s %s %d",
               msg_hmth_du,l_month[cur_month-1],cur_year);
      month_graph6 (  png1_fname,          /* filename          */
                      dtitle,              /* graph title       */
                      cur_month,           /* graph month       */
                      cur_year,            /* graph year        */
                      tm_hit,              /* data 1 (hits)     */
                      tm_file,             /* data 2 (files)    */
                      tm_site,             /* data 3 (sites)    */
                      tm_xfer,             /* data 4 (kbytes)   */
                      tm_page,             /* data 5 (pages)    */
                      tm_visit);           /* data 6 (visits)   */
   }

   if (hourly_graph)
   {
      snprintf(htitle,sizeof(htitle),"%s %s %d",
               msg_hmth_hu,l_month[cur_month-1],cur_year);
      day_graph3(    png2_fname,
                     htitle,
                     th_hit,
                     th_file,
                     th_page );
   }

   /* now do html stuff... */
   /* first, open the file */
   if ( (out_fp=open_out_file(html_fname))==NULL ) return 1;

   snprintf(buffer,sizeof(buffer),"%s %d",l_month[cur_month-1],cur_year);
   write_html_head(buffer, out_fp);
   month_links();
   month_total_table();
   if (daily_graph || daily_stats)        /* Daily stuff */
   {
      fprintf(out_fp,"<A NAME=\"DAYSTATS\"></A>\n");
      if (daily_graph) fprintf(out_fp,"<IMG SRC=\"%s\" ALT=\"%s\" " \
                  "HEIGHT=400 WIDTH=512><P>\n",png1_fname,dtitle);
      if (daily_stats) daily_total_table();
   }

   if (hourly_graph || hourly_stats)      /* Hourly stuff */
   {
      fprintf(out_fp,"<A NAME=\"HOURSTATS\"></A>\n");
      if (hourly_graph) fprintf(out_fp,"<IMG SRC=\"%s\" ALT=\"%s\" "  \
                     "HEIGHT=256 WIDTH=512><P>\n",png2_fname,htitle);
      if (hourly_stats) hourly_total_table();
   }

   /* Do URL related stuff here, sorting appropriately                      */
   if ( (a_ctr=load_url_array(NULL)) )
   {
    if ( (u_array=malloc(sizeof(UNODEPTR)*(a_ctr))) !=NULL )
    {
     a_ctr=load_url_array(u_array);        /* load up our sort array        */
     if (ntop_urls || dump_urls)
     {
       qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmph);
       if (ntop_urls) top_urls_table(0);   /* Top URLs (by hits)            */
       if (dump_urls) dump_all_urls();     /* Dump URLs tab file            */
     }
     if (ntop_urlsK)                       /* Top URLs (by kbytes)          */
      {qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmpk); top_urls_table(1); }
     if (ntop_entry)                       /* Top Entry Pages               */
      {qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmpn); top_entry_table(0);}
     if (ntop_exit)                        /* Top Exit Pages                */
      {qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmpx); top_entry_table(1);}
     free(u_array);
    }
    else if (verbose) fprintf(stderr,"%s [u_array]\n",msg_nomem_tu); /* err */
   }

   /* do hostname (sites) related stuff here, sorting appropriately...      */
   if ( (a_ctr=load_site_array(NULL)) )
   {
    if ( (h_array=malloc(sizeof(HNODEPTR)*(a_ctr))) !=NULL )
    {
     a_ctr=load_site_array(h_array);       /* load up our sort array        */
     if (ntop_sites || dump_sites)
     {
       qsort(h_array,a_ctr,sizeof(HNODEPTR),qs_site_cmph);
       if (ntop_sites) top_sites_table(0); /* Top sites table (by hits)     */
       if (dump_sites) dump_all_sites();   /* Dump sites tab file           */
     }
     if (ntop_sitesK)                      /* Top Sites table (by kbytes)   */
     {
       qsort(h_array,a_ctr,sizeof(HNODEPTR),qs_site_cmpk);
       top_sites_table(1);
     }
     free(h_array);
    }
    else if (verbose) fprintf(stderr,"%s [h_array]\n",msg_nomem_ts); /* err */
   }

   /* do referrer related stuff here, sorting appropriately...              */
   if ( (a_ctr=load_ref_array(NULL)) )
   {
    if ( (r_array=malloc(sizeof(RNODEPTR)*(a_ctr))) != NULL)
    {
     a_ctr=load_ref_array(r_array);
     if (ntop_refs || dump_refs)
     {
       qsort(r_array,a_ctr,sizeof(RNODEPTR),qs_ref_cmph);
       if (ntop_refs) top_refs_table();   /* Top referrers table            */
       if (dump_refs) dump_all_refs();    /* Dump referrers tab file        */
     }
     free(r_array);
    }
    else if (verbose) fprintf(stderr,"%s [r_array]\n",msg_nomem_tr); /* err */
   }

   /* do search string related stuff, sorting appropriately...              */
   if ( (a_ctr=load_srch_array(NULL)) )
   {
    if ( (s_array=malloc(sizeof(SNODEPTR)*(a_ctr))) != NULL)
    {
     a_ctr=load_srch_array(s_array);
     if (ntop_search || dump_search)
     {
       qsort(s_array,a_ctr,sizeof(SNODEPTR),qs_srch_cmph);
       if (ntop_search) top_search_table(); /* top search strings table     */
       if (dump_search) dump_all_search();  /* dump search string tab file  */
     }
     free(s_array);
    }
    else if (verbose) fprintf(stderr,"%s [s_array]\n",msg_nomem_tsr);/* err */
   }

   /* do ident (username) related stuff here, sorting appropriately...      */
   if ( (a_ctr=load_ident_array(NULL)) )
   {
    if ( (i_array=malloc(sizeof(INODEPTR)*(a_ctr))) != NULL)
    {
     a_ctr=load_ident_array(i_array);
     if (ntop_users || dump_users)
     {
       qsort(i_array,a_ctr,sizeof(INODEPTR),qs_ident_cmph);
       if (ntop_users) top_users_table(); /* top usernames table            */
       if (dump_users) dump_all_users();  /* dump usernames tab file        */
     }
     free(i_array);
    }
    else if (verbose) fprintf(stderr,"%s [i_array]\n",msg_nomem_ti); /* err */
   }

   /* do user agent related stuff here, sorting appropriately...            */
   if ( (a_ctr=load_agent_array(NULL)) )
   {
    if ( (a_array=malloc(sizeof(ANODEPTR)*(a_ctr))) != NULL)
    {
     a_ctr=load_agent_array(a_array);
     if (ntop_agents || dump_agents)
     {
       qsort(a_array,a_ctr,sizeof(ANODEPTR),qs_agnt_cmph);
       if (ntop_agents) top_agents_table(); /* top user agents table        */
       if (dump_agents) dump_all_agents();  /* dump user agents tab file    */
     }
     free(a_array);
    }
    else if (verbose) fprintf(stderr,"%s [a_array]\n",msg_nomem_ta); /* err */
   }

   if (ntop_ctrys ) top_ctry_table();     /* top countries table            */

   write_html_tail(out_fp);               /* finish up the HTML document    */
   fclose(out_fp);                        /* close the file                 */
   return (0);                            /* done...                        */
}

/*********************************************/
/* MONTH_LINKS - links to other page parts   */
/*********************************************/

void month_links()
{
   fprintf(out_fp,"<SMALL>\n");
   if (daily_stats || daily_graph)
      fprintf(out_fp,"<A HREF=\"#DAYSTATS\">[%s]</A>\n",msg_hlnk_ds);
   if (hourly_stats || hourly_graph)
      fprintf(out_fp,"<A HREF=\"#HOURSTATS\">[%s]</A>\n",msg_hlnk_hs);
   if (ntop_urls || ntop_urlsK)
      fprintf(out_fp,"<A HREF=\"#TOPURLS\">[%s]</A>\n",msg_hlnk_u);
   if (ntop_entry)
      fprintf(out_fp,"<A HREF=\"#TOPENTRY\">[%s]</A>\n",msg_hlnk_en);
   if (ntop_exit)
      fprintf(out_fp,"<A HREF=\"#TOPEXIT\">[%s]</A>\n",msg_hlnk_ex);
   if (ntop_sites || ntop_sitesK)
      fprintf(out_fp,"<A HREF=\"#TOPSITES\">[%s]</A>\n",msg_hlnk_s);
   if (ntop_refs && t_ref)
      fprintf(out_fp,"<A HREF=\"#TOPREFS\">[%s]</A>\n",msg_hlnk_r);
   if (ntop_search)
      fprintf(out_fp,"<A HREF=\"#TOPSEARCH\">[%s]</A>\n",msg_hlnk_sr);
   if (ntop_users && t_user)
      fprintf(out_fp,"<A HREF=\"#TOPUSERS\">[%s]</A>\n",msg_hlnk_i);
   if (ntop_agents && t_agent)
      fprintf(out_fp,"<A HREF=\"#TOPAGENTS\">[%s]</A>\n",msg_hlnk_a);
   if (ntop_ctrys)
      fprintf(out_fp,"<A HREF=\"#TOPCTRYS\">[%s]</A>\n",msg_hlnk_c);
   fprintf(out_fp,"</SMALL>\n<P>\n");
}

/*********************************************/
/* MONTH_TOTAL_TABLE - monthly totals table  */
/*********************************************/

void month_total_table()
{
   int i,days_in_month;
   u_int64_t max_files=0,max_hits=0,max_visits=0,max_pages=0,max_sites=0;
   double max_xfer=0.0;

   days_in_month=(l_day-f_day)+1;
   for (i=0;i<31;i++)
   {  /* Get max/day values */
      if (tm_hit[i]>max_hits)     max_hits  = tm_hit[i];
      if (tm_file[i]>max_files)   max_files = tm_file[i];
      if (tm_page[i]>max_pages)   max_pages = tm_page[i];
      if (tm_visit[i]>max_visits) max_visits= tm_visit[i];
      if (tm_site[i]>max_sites)   max_sites = tm_site[i];
      if (tm_xfer[i]>max_xfer)    max_xfer  = tm_xfer[i];
   }

   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH COLSPAN=3 ALIGN=center BGCOLOR=\"%s\">"           \
      "%s %s %d</TH></TR>\n",GREY,msg_mtot_ms,l_month[cur_month-1],cur_year);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   /* Total Hits */
   fprintf(out_fp,"<TR><TD WIDTH=380><FONT SIZE=\"-1\">%s</FONT></TD>\n"     \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_mtot_th,t_hit);
   /* Total Files */
   fprintf(out_fp,"<TR><TD WIDTH=380><FONT SIZE=\"-1\">%s</FONT></TD>\n"     \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_mtot_tf,t_file);
   /* Total Pages */
   fprintf(out_fp,"<TR><TD WIDTH=380><FONT SIZE=\"-1\">%s %s</FONT></TD>\n"  \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_h_total, msg_h_pages, t_page);
   /* Total Visits */
   fprintf(out_fp,"<TR><TD WIDTH=380><FONT SIZE=\"-1\">%s %s</FONT></TD>\n"  \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_h_total, msg_h_visits, t_visit);
   /* Total XFer */
   fprintf(out_fp,"<TR><TD WIDTH=380><FONT SIZE=\"-1\">%s</FONT></TD>\n"     \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%.0f</B>"              \
      "</FONT></TD></TR>\n",msg_mtot_tx,t_xfer/1024);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   /**********************************************/
   /* Unique Sites */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD WIDTH=380><FONT SIZE=\"-1\">%s</FONT></TD>\n"                     \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_mtot_us,t_site);
   /* Unique URLs */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD WIDTH=380><FONT SIZE=\"-1\">%s</FONT></TD>\n"                     \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_mtot_uu,t_url);
   /* Unique Referrers */
   if (t_ref != 0)
   fprintf(out_fp,"<TR>"                                                     \
      "<TD WIDTH=380><FONT SIZE=\"-1\">%s</FONT></TD>\n"                     \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_mtot_ur,t_ref);
   /* Unique Usernames */
   if (t_user != 0)
   fprintf(out_fp,"<TR>"                                                     \
      "<TD WIDTH=380><FONT SIZE=\"-1\">%s</FONT></TD>\n"                     \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_mtot_ui,t_user);
   /* Unique Agents */
   if (t_agent != 0)
   fprintf(out_fp,"<TR>"                                                     \
      "<TD WIDTH=380><FONT SIZE=\"-1\">%s</FONT></TD>\n"                     \
      "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%llu</B>"              \
      "</FONT></TD></TR>\n",msg_mtot_ua,t_agent);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   /**********************************************/
   /* Hourly/Daily avg/max totals */
   fprintf(out_fp,"<TR>"                                                     \
      "<TH WIDTH=380 BGCOLOR=\"%s\"><FONT SIZE=-1 COLOR=\"%s\">.</FONT></TH>\n"\
      "<TH WIDTH=65 BGCOLOR=\"%s\" ALIGN=right>"                             \
      "<FONT SIZE=-1>%s </FONT></TH>\n"                                      \
      "<TH WIDTH=65 BGCOLOR=\"%s\" ALIGN=right>"                             \
      "<FONT SIZE=-1>%s </FONT></TH></TR>\n",
      GREY,GREY,GREY,msg_h_avg,GREY,msg_h_max);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   /* Max/Avg Hits per Hour */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"                               \
      "<TD ALIGN=right WIDTH=65><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
      "<TD WIDTH=65 ALIGN=right><FONT SIZE=-1><B>%llu</B>"                   \
      "</FONT></TD></TR>\n",msg_mtot_mhh, t_hit/(24*days_in_month),mh_hit);
   /* Max/Avg Hits per Day */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"                               \
      "<TD ALIGN=right WIDTH=65><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
      "<TD WIDTH=65 ALIGN=right><FONT SIZE=-1><B>%llu</B>"                   \
      "</FONT></TD></TR>\n",msg_mtot_mhd, t_hit/days_in_month, max_hits);
   /* Max/Avg Files per Day */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"                               \
      "<TD ALIGN=right WIDTH=65><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
      "<TD WIDTH=65 ALIGN=right><FONT SIZE=-1><B>%llu</B>"                   \
      "</FONT></TD></TR>\n",msg_mtot_mfd, t_file/days_in_month,max_files);
   /* Max/Avg Pages per Day */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"                               \
      "<TD ALIGN=right WIDTH=65><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
      "<TD WIDTH=65 ALIGN=right><FONT SIZE=-1><B>%llu</B>"                   \
      "</FONT></TD></TR>\n",msg_mtot_mpd, t_page/days_in_month,max_pages);
   /* Max/Avg Sites per Day */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"                               \
      "<TD ALIGN=right WIDTH=65><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
      "<TD WIDTH=65 ALIGN=right><FONT SIZE=-1><B>%llu</B>"                   \
      "</FONT></TD></TR>\n",msg_mtot_msd, t_site/days_in_month,max_sites);
   /* Max/Avg Visits per Day */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"                               \
      "<TD ALIGN=right WIDTH=65><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
      "<TD WIDTH=65 ALIGN=right><FONT SIZE=-1><B>%llu</B>"                   \
      "</FONT></TD></TR>\n",msg_mtot_mvd, t_visit/days_in_month,max_visits);
   /* Max/Avg KBytes per Day */
   fprintf(out_fp,"<TR>"                                                     \
      "<TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"                               \
      "<TD ALIGN=right WIDTH=65><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n" \
      "<TD WIDTH=65 ALIGN=right><FONT SIZE=-1><B>%.0f</B>"                   \
      "</FONT></TD></TR>\n",msg_mtot_mkd,
      (t_xfer/1024)/days_in_month,max_xfer/1024);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   /**********************************************/
   /* response code totals */
   fprintf(out_fp,"<TR><TH COLSPAN=3 ALIGN=center BGCOLOR=\"%s\">\n"         \
           "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",GREY,msg_mtot_rc);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   for (i=0;i<TOTAL_RC;i++)
   {
      if (response[i].count != 0)
         fprintf(out_fp,"<TR><TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"         \
            "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"       \
            "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD></TR>\n",
            response[i].desc,PCENT(response[i].count,t_hit),response[i].count);
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   /**********************************************/

   fprintf(out_fp,"</TABLE>\n");
   fprintf(out_fp,"<P>\n");
}

/*********************************************/
/* DAILY_TOTAL_TABLE - daily totals          */
/*********************************************/

void daily_total_table()
{
   int i,j;

   /* Daily stats */
   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   /* Daily statistics for ... */
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" COLSPAN=13 ALIGN=center>"          \
           "%s %s %d</TH></TR>\n",
           GREY,msg_dtot_ds,l_month[cur_month-1], cur_year);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH ALIGN=center BGCOLOR=\"%s\">"                     \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"                       \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"               \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"                       \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"               \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"                       \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"               \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"                       \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"               \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"                       \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"               \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"                       \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"               \
                  "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",
                  GREY,       msg_h_day,
                  HITCOLOR,   msg_h_hits,
                  FILECOLOR,  msg_h_files,
                  PAGECOLOR,  msg_h_pages,
                  VISITCOLOR, msg_h_visits,
                  SITECOLOR,  msg_h_sites,
                  KBYTECOLOR, msg_h_xfer);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   /* skip beginning blank days in a month */
   for (i=0;i<l_day;i++) if (tm_hit[i]!=0) break;
   if (i==l_day) i=0;

   for (;i<l_day;i++)
   {
      j = jdate(i+1,cur_month,cur_year);
      if ( (j%7==6) || (j%7==0) )
           fprintf(out_fp,"<TR BGCOLOR=\"%s\"><TD ALIGN=center>",GRPCOLOR);
      else fprintf(out_fp,"<TR><TD ALIGN=center>");
      fprintf(out_fp,"<FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n", i+1);
      fprintf(out_fp,"<TD ALIGN=right>"                                      \
              "<FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"                  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n",
              tm_hit[i],PCENT(tm_hit[i],t_hit));
      fprintf(out_fp,"<TD ALIGN=right>"                                      \
              "<FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"                  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n",
              tm_file[i],PCENT(tm_file[i],t_file));
      fprintf(out_fp,"<TD ALIGN=right>"                                      \
              "<FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"                  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n",
              tm_page[i],PCENT(tm_page[i],t_page));
      fprintf(out_fp,"<TD ALIGN=right>"                                      \
              "<FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"                  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n",
              tm_visit[i],PCENT(tm_visit[i],t_visit));
      fprintf(out_fp,"<TD ALIGN=right>"                                      \
              "<FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"                  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n",
              tm_site[i],PCENT(tm_site[i],t_site));
      fprintf(out_fp,"<TD ALIGN=right>"                                      \
              "<FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n"                  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD></TR>\n",
              tm_xfer[i]/1024,PCENT(tm_xfer[i],t_xfer));
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"</TABLE>\n");
   fprintf(out_fp,"<P>\n");
}

/*********************************************/
/* HOURLY_TOTAL_TABLE - hourly table         */
/*********************************************/

void hourly_total_table()
{
   int       i,days_in_month;
   u_int64_t avg_file=0;
   double    avg_xfer=0.0;

   days_in_month=(l_day-f_day)+1;

   /* Hourly stats */
   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" COLSPAN=13 ALIGN=center>"\
           "%s %s %d</TH></TR>\n",
           GREY,msg_htot_hs,l_month[cur_month-1], cur_year);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH ALIGN=center ROWSPAN=2 BGCOLOR=\"%s\">" \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"             \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=3>"     \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"             \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=3>"     \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"             \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=3>"     \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n"             \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=3>"     \
                  "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",
                  GREY,       msg_h_hour,
                  HITCOLOR,   msg_h_hits,
                  FILECOLOR,  msg_h_files,
                  PAGECOLOR,  msg_h_pages,
                  KBYTECOLOR, msg_h_xfer);
   fprintf(out_fp,"<TR><TH ALIGN=center BGCOLOR=\"%s\">"           \
                  "<FONT SIZE=\"-2\">%s</FONT></TH>\n"             \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"     \
                  "<FONT SIZE=\"-2\">%s</FONT></TH>\n",
                  HITCOLOR, msg_h_avg, HITCOLOR, msg_h_total);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"               \
                  "<FONT SIZE=\"-2\">%s</FONT></TH>\n"             \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"     \
                  "<FONT SIZE=\"-2\">%s</FONT></TH>\n",
                  FILECOLOR, msg_h_avg, FILECOLOR, msg_h_total);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"               \
                  "<FONT SIZE=\"-2\">%s</FONT></TH>\n"             \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"     \
                  "<FONT SIZE=\"-2\">%s</FONT></TH>\n",
                  PAGECOLOR, msg_h_avg, PAGECOLOR, msg_h_total);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"               \
                  "<FONT SIZE=\"-2\">%s</FONT></TH>\n"             \
                  "<TH ALIGN=center BGCOLOR=\"%s\" COLSPAN=2>"     \
                  "<FONT SIZE=\"-2\">%s</FONT></TH></TR>\n",
                  KBYTECOLOR, msg_h_avg, KBYTECOLOR, msg_h_total);

   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   for (i=0;i<24;i++)
   {
      fprintf(out_fp,"<TR><TD ALIGN=center>"                          \
         "<FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n",i);
      fprintf(out_fp,
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
         "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n",
         th_hit[i]/days_in_month,th_hit[i],
         PCENT(th_hit[i],t_hit));
      fprintf(out_fp,
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
         "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n",
         th_file[i]/days_in_month,th_file[i],
         PCENT(th_file[i],t_file));
      fprintf(out_fp,
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
         "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n",
         th_page[i]/days_in_month,th_page[i],
         PCENT(th_page[i],t_page));
      fprintf(out_fp,
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n" \
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n" \
         "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD></TR>\n",
         (th_xfer[i]/days_in_month)/1024,th_xfer[i]/1024,
         PCENT(th_xfer[i],t_xfer));
      avg_file += th_file[i]/days_in_month;
      avg_xfer+= (th_xfer[i]/days_in_month)/1024;
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* TOP_SITES_TABLE - generate top n table    */
/*********************************************/

void top_sites_table(int flag)
{
   u_int64_t cnt=0, h_reg=0, h_grp=0, h_hid=0, tot_num;
   int       i;
   HNODEPTR  hptr, *pointer;

   cnt=a_ctr; pointer=h_array;
   while(cnt--)
   {
      /* calculate totals */
      switch ( (int)((HNODEPTR)(*pointer)->flag) )
      {
         case OBJ_REG:   h_reg++;  break;
         case OBJ_GRP:   h_grp++;  break;
         case OBJ_HIDE:  h_hid++;  break;
      }
      pointer++;
   }

   if ( (tot_num=h_reg+h_grp)==0 ) return;              /* split if none    */
   i=(flag)?ntop_sitesK:ntop_sites;                     /* Hits or KBytes?? */
   if (tot_num > i) tot_num = i;                        /* get max to do... */

   if ((!flag) || (flag&&!ntop_sites))                  /* now do <A> tag   */
      fprintf(out_fp,"<A NAME=\"TOPSITES\"></A>\n");

   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if (flag) fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=10>" \
           "%s %llu %s %llu %s %s %s</TH></TR>\n",
           GREY, msg_top_top,tot_num,msg_top_of,
           t_site,msg_top_s,msg_h_by,msg_h_xfer);
   else      fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=10>" \
           "%s %llu %s %llu %s</TH></TR>\n",
           GREY,msg_top_top, tot_num, msg_top_of, t_site, msg_top_s);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                    \
          "<FONT SIZE=\"-1\">#</FONT></TH>\n",GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"              \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"              \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",FILECOLOR,msg_h_files);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"              \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",KBYTECOLOR,msg_h_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"              \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",VISITCOLOR,msg_h_visits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                        \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",MISCCOLOR,msg_h_hname);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   pointer=h_array; i=0;
   while(tot_num)
   {
      hptr=*pointer++;
      if (hptr->flag != OBJ_HIDE)
      {
         /* shade grouping? */
         if (shade_groups && (hptr->flag==OBJ_GRP))
            fprintf(out_fp,"<TR BGCOLOR=\"%s\">\n", GRPCOLOR);
         else fprintf(out_fp,"<TR>\n");

         fprintf(out_fp,
              "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n"  \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">",
              i+1,hptr->count,
              (t_hit==0)?0:((float)hptr->count/t_hit)*100.0,hptr->files,
              (t_file==0)?0:((float)hptr->files/t_file)*100.0,hptr->xfer/1024,
              (t_xfer==0)?0:((float)hptr->xfer/t_xfer)*100.0,hptr->visit,
              (t_visit==0)?0:((float)hptr->visit/t_visit)*100.0);

         if ((hptr->flag==OBJ_GRP)&&hlite_groups)
             fprintf(out_fp,"<STRONG>%s</STRONG></FONT></TD></TR>\n",
               hptr->string);
         else fprintf(out_fp,"%s</FONT></TD></TR>\n",
               hptr->string);
         tot_num--;
         i++;
      }
   }

   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if ((!flag) || (flag&&!ntop_sites))
   {
      if ( (all_sites) && ((h_reg+h_grp)>ntop_sites) )
      {
         if (all_sites_page(h_reg, h_grp))
         {
            fprintf(out_fp,"<TR BGCOLOR=\"%s\">",GRPCOLOR);
            fprintf(out_fp,"<TD COLSPAN=10 ALIGN=\"center\">\n");
            fprintf(out_fp,"<FONT SIZE=\"-1\">");
            fprintf(out_fp,"<A HREF=\"./site_%04d%02d.%s\">",
                    cur_year,cur_month,html_ext);
            fprintf(out_fp,"%s</A></TD></TR>\n",msg_v_sites);
            if (flag)   /* do we need to sort? */
               qsort(h_array,a_ctr,sizeof(HNODEPTR),qs_site_cmph);
         }
      }
   }
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* ALL_SITES_PAGE - HTML page of all sites   */
/*********************************************/

int all_sites_page(u_int64_t h_reg, u_int64_t h_grp)
{
   HNODEPTR hptr, *pointer;
   char     site_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(h_grp)?1:0;

   /* generate file name */
   snprintf(site_fname,sizeof(site_fname),"site_%04d%02d.%s",
            cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(site_fname))==NULL ) return 0;

   snprintf(buffer,sizeof(buffer),"%s %d - %s",
            l_month[cur_month-1],cur_year,msg_h_sites);
   write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %12s      %12s      %12s      %s\n",
           msg_h_hits, msg_h_files, msg_h_xfer, msg_h_visits, msg_h_hname);
   fprintf(out_fp,"----------------  ----------------  ----------------  " \
                  "----------------  --------------------\n\n");

   /* Do groups first (if any) */
   pointer=h_array;
   while(h_grp)
   {
      hptr=*pointer++;
      if (hptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,
            "%-8llu %6.02f%%  %8llu %6.02f%%  %8.0f %6.02f%%  "            \
            "%8llu %6.02f%%  %s\n",
            hptr->count,
            (t_hit==0)?0:((float)hptr->count/t_hit)*100.0,hptr->files,
            (t_file==0)?0:((float)hptr->files/t_file)*100.0,hptr->xfer/1024,
            (t_xfer==0)?0:((float)hptr->xfer/t_xfer)*100.0,hptr->visit,
            (t_visit==0)?0:((float)hptr->visit/t_visit)*100.0,
            hptr->string);
         h_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   /* Now do individual sites (if any) */
   pointer=h_array;
   if (!hide_sites) while(h_reg)
   {
      hptr=*pointer++;
      if (hptr->flag == OBJ_REG)
      {
         fprintf(out_fp,
            "%-8llu %6.02f%%  %8llu %6.02f%%  %8.0f %6.02f%%  "            \
            "%8llu %6.02f%%  %s\n",
            hptr->count,
            (t_hit==0)?0:((float)hptr->count/t_hit)*100.0,hptr->files,
            (t_file==0)?0:((float)hptr->files/t_file)*100.0,hptr->xfer/1024,
            (t_xfer==0)?0:((float)hptr->xfer/t_xfer)*100.0,hptr->visit,
            (t_visit==0)?0:((float)hptr->visit/t_visit)*100.0,
            hptr->string);
         h_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_URLS_TABLE - generate top n table     */
/*********************************************/

void top_urls_table(int flag)
{
   u_int64_t cnt=0,u_reg=0,u_grp=0,u_hid=0, tot_num;
   int       i;
   UNODEPTR  uptr, *pointer;

   cnt=a_ctr; pointer=u_array;
   while (cnt--)
   {
      /* calculate totals */
      switch ( (int)((UNODEPTR)(*pointer)->flag) )
      {
         case OBJ_REG:  u_reg++;  break;
         case OBJ_GRP:  u_grp++;  break;
         case OBJ_HIDE: u_hid++;  break;
      }
      pointer++;
   }

   if ( (tot_num=u_reg+u_grp)==0 ) return;              /* split if none    */
   i=(flag)?ntop_urlsK:ntop_urls;                       /* Hits or KBytes?? */
   if (tot_num > i) tot_num = i;                        /* get max to do... */
   if ((!flag) || (flag&&!ntop_urls))                   /* now do <A> tag   */
      fprintf(out_fp,"<A NAME=\"TOPURLS\"></A>\n");

   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if (flag) fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=6>"  \
           "%s %llu %s %llu %s %s %s</TH></TR>\n",
           GREY,msg_top_top,tot_num,msg_top_of,
           t_url,msg_top_u,msg_h_by,msg_h_xfer);
   else fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=6>"   \
           "%s %llu %s %llu %s</TH></TR>\n",
           GREY,msg_top_top,tot_num,msg_top_of,t_url,msg_top_u);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                  \
                  "<FONT SIZE=\"-1\">#</FONT></TH>\n",GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"            \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n",
                  HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"            \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n",
                  KBYTECOLOR,msg_h_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                      \
                  "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",
                  MISCCOLOR,msg_h_url);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   pointer=u_array; i=0;
   while (tot_num)
   {
      uptr=*pointer++;             /* point to the URL node */
      if (uptr->flag != OBJ_HIDE)
      {
         /* shade grouping? */
         if (shade_groups && (uptr->flag==OBJ_GRP))
            fprintf(out_fp,"<TR BGCOLOR=\"%s\">\n", GRPCOLOR);
         else fprintf(out_fp,"<TR>\n");

         fprintf(out_fp,
            "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n" \
            "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
            "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
            "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n"\
            "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
            "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">",
            i+1,uptr->count,
            (t_hit==0)?0:((float)uptr->count/t_hit)*100.0,
            uptr->xfer/1024,
            (t_xfer==0)?0:((float)uptr->xfer/t_xfer)*100.0);

         if (uptr->flag==OBJ_GRP)
         {
            if (hlite_groups)
               fprintf(out_fp,"<STRONG>%s</STRONG></FONT></TD></TR>\n",
                uptr->string);
            else fprintf(out_fp,"%s</FONT></TD></TR>\n",uptr->string);
         }
         else 
	 {
            /* check for a service prefix (ie: http://) */
            if (strstr(uptr->string,"://")!=NULL)
               fprintf(out_fp,"<A HREF=\"%s\">%s</A></FONT></TD></TR>\n",
                 uptr->string,uptr->string);
	    else
            {
               if (log_type == LOG_FTP) /* FTP log? */
                   fprintf(out_fp,"%s</FONT></TD></TR>\n",uptr->string);
               else
               {             /* Web log  */
                  if (use_https)
                     /* secure server mode, use https:// */
                     fprintf(out_fp,
                     "<A HREF=\"https://%s%s\">%s</A></FONT></TD></TR>\n",
                      hname,uptr->string,uptr->string);
                   else
                      /* otherwise use standard 'http://' */
                      fprintf(out_fp,
                      "<A HREF=\"http://%s%s\">%s</A></FONT></TD></TR>\n",
                      hname,uptr->string,uptr->string);
               }
            }
	 }
         tot_num--;
         i++;
      }
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if ((!flag) || (flag&&!ntop_urls))
   {
      if ( (all_urls) && ((u_reg+u_grp)>ntop_urls) )
      {
         if (all_urls_page(u_reg, u_grp))
         {
            fprintf(out_fp,"<TR BGCOLOR=\"%s\">",GRPCOLOR);
            fprintf(out_fp,"<TD COLSPAN=6 ALIGN=\"center\">\n");
            fprintf(out_fp,"<FONT SIZE=\"-1\">");
            fprintf(out_fp,"<A HREF=\"./url_%04d%02d.%s\">",
                    cur_year,cur_month,html_ext);
            fprintf(out_fp,"%s</A></TD></TR>\n",msg_v_urls);
            if (flag)   /* do we need to sort first? */
               qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmph);
         }
      }
   }
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* ALL_URLS_PAGE - HTML page of all urls     */
/*********************************************/

int all_urls_page(u_int64_t u_reg, u_int64_t u_grp)
{
   UNODEPTR uptr, *pointer;
   char     url_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(u_grp)?1:0;

   /* generate file name */
   snprintf(url_fname,sizeof(url_fname),"url_%04d%02d.%s",
            cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(url_fname))==NULL ) return 0;

   snprintf(buffer,sizeof(buffer),"%s %d - %s",
            l_month[cur_month-1],cur_year,msg_h_url);
   write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %12s      %s\n",
           msg_h_hits,msg_h_xfer,msg_h_url);
   fprintf(out_fp,"----------------  ----------------  " \
                  "--------------------\n\n");

   /* do groups first (if any) */
   pointer=u_array;
   while (u_grp)
   {
      uptr=*pointer++;
      if (uptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,"%-8llu %6.02f%%  %8.0f %6.02f%%  %s\n",
            uptr->count,
            (t_hit==0)?0:((float)uptr->count/t_hit)*100.0,
            uptr->xfer/1024,
            (t_xfer==0)?0:((float)uptr->xfer/t_xfer)*100.0,
            uptr->string);
         u_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   /* now do invididual sites (if any) */
   pointer=u_array;
   while (u_reg)
   {
      uptr=*pointer++;
      if (uptr->flag == OBJ_REG)
      {
         fprintf(out_fp,"%-8llu %6.02f%%  %8.0f %6.02f%%  %s\n",
            uptr->count,
            (t_hit==0)?0:((float)uptr->count/t_hit)*100.0,
            uptr->xfer/1024,
            (t_xfer==0)?0:((float)uptr->xfer/t_xfer)*100.0,
            uptr->string);
         u_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_ENTRY_TABLE - top n entry/exit urls   */
/*********************************************/

void top_entry_table(int flag)
{
   u_int64_t cnt=0, u_entry=0, u_exit=0, tot_num;
   u_int64_t t_entry=0, t_exit=0;
   int       i;
   UNODEPTR  uptr, *pointer;

   cnt=a_ctr; pointer=u_array;
   while (cnt--)
   {
      if ( (int)((UNODEPTR)(*pointer)->flag) == OBJ_REG )
      {
         if ( (u_int64_t)(((UNODEPTR)(*pointer))->entry) )
            {  u_entry++; t_entry+=(u_int64_t)(((UNODEPTR)(*pointer))->entry); }
         if ( (u_int64_t)(((UNODEPTR)(*pointer))->exit)  )
            { u_exit++;   t_exit +=(u_int64_t)(((UNODEPTR)(*pointer))->exit);  }
      }
      pointer++;
   }

   /* calculate how many we have */
   tot_num=(flag)?u_exit:u_entry;
   if (flag) { if (tot_num > ntop_exit ) tot_num=ntop_exit;  }
   else      { if (tot_num > ntop_entry) tot_num=ntop_entry; }

   /* return if none to do */
   if (!tot_num) return;

   if (flag) fprintf(out_fp,"<A NAME=\"TOPEXIT\"></A>\n"); /* do anchor tag */
   else      fprintf(out_fp,"<A NAME=\"TOPENTRY\"></A>\n");

   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=6>"        \
           "%s %llu %s %llu %s</TH></TR>\n",
           GREY,msg_top_top,tot_num,msg_top_of,
           (flag)?u_exit:u_entry,(flag)?msg_top_ex:msg_top_en);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                  \
                  "<FONT SIZE=\"-1\">#</FONT></TH>\n",
                  GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"            \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n",
                  HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"            \
                  "<FONT SIZE=\"-1\">%s</FONT></TH>\n",
                  VISITCOLOR,msg_h_visits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                      \
                  "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",
                  MISCCOLOR,msg_h_url);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   pointer=u_array; i=0;
   while (tot_num)
   {
      uptr=*pointer++;
      if (uptr->flag != OBJ_HIDE)
      {
         fprintf(out_fp,"<TR>\n");
         fprintf(out_fp,
             "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n" \
             "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
             "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
             "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
             "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
             "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">",
             i+1,uptr->count,
             (t_hit==0)?0:((float)uptr->count/t_hit)*100.0,
             (flag)?uptr->exit:uptr->entry,
             (flag)?((t_exit==0)?0:((float)uptr->exit/t_exit)*100.0)
                   :((t_entry==0)?0:((float)uptr->entry/t_entry)*100.0));

         /* check for a service prefix (ie: http://) */
         if (strstr(uptr->string,"://")!=NULL)
          fprintf(out_fp,
             "<A HREF=\"%s\">%s</A></FONT></TD></TR>\n",
              uptr->string,uptr->string);
	 else
         {
            if (use_https)
            /* secure server mode, use https:// */
             fprintf(out_fp,
                "<A HREF=\"https://%s%s\">%s</A></FONT></TD></TR>\n",
                 hname,uptr->string,uptr->string);
            else
            /* otherwise use standard 'http://' */
             fprintf(out_fp,
                "<A HREF=\"http://%s%s\">%s</A></FONT></TD></TR>\n",
                 hname,uptr->string,uptr->string);
	 }
         tot_num--;
         i++;
      }
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* TOP_REFS_TABLE - generate top n table     */
/*********************************************/

void top_refs_table()
{
   u_int64_t cnt=0, r_reg=0, r_grp=0, r_hid=0, tot_num;
   int       i;
   RNODEPTR  rptr, *pointer;

   if (t_ref==0) return;        /* return if none to process */

   cnt=a_ctr; pointer=r_array;
   while(cnt--)
   {
      /* calculate totals */
      switch ( (int)((RNODEPTR)(*pointer)->flag) )
      {
         case OBJ_REG:  r_reg++;  break;
         case OBJ_HIDE: r_hid++;  break;
         case OBJ_GRP:  r_grp++;  break;
      }
      pointer++;
   }

   if ( (tot_num=r_reg+r_grp)==0 ) return;              /* split if none    */
   if (tot_num > ntop_refs) tot_num=ntop_refs;          /* get max to do... */

   fprintf(out_fp,"<A NAME=\"TOPREFS\"></A>\n");
   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=4>"         \
           "%s %llu %s %llu %s</TH></TR>\n",
           GREY, msg_top_top, tot_num, msg_top_of, t_ref, msg_top_r);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                   \
          "<FONT SIZE=\"-1\">#</FONT></TH>\n",
          GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",
          HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                       \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",
          MISCCOLOR,msg_h_ref);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   pointer=r_array; i=0;
   while(tot_num)
   {
      rptr=*pointer++;
      if (rptr->flag != OBJ_HIDE)
      {
         /* shade grouping? */
         if (shade_groups && (rptr->flag==OBJ_GRP))
            fprintf(out_fp,"<TR BGCOLOR=\"%s\">\n", GRPCOLOR);
         else fprintf(out_fp,"<TR>\n");

         fprintf(out_fp,
             "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n"  \
             "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
             "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
             "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">",
             i+1,rptr->count,
             (t_hit==0)?0:((float)rptr->count/t_hit)*100.0);

         if (rptr->flag==OBJ_GRP)
         {
            if (hlite_groups)
               fprintf(out_fp,"<STRONG>%s</STRONG>",rptr->string);
            else fprintf(out_fp,"%s",rptr->string);
         }
         else
         {
            /* only link if enabled and has a service prefix */
            if ( (strstr(rptr->string,"://")!=NULL) && link_referrer )
               fprintf(out_fp,"<A HREF=\"%s\" rel=\"nofollow\">%s</A>",
                       rptr->string, rptr->string);
            else
               fprintf(out_fp,"%s", rptr->string);
         }
         fprintf(out_fp,"</FONT></TD></TR>\n");
         tot_num--;
         i++;
      }
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if ( (all_refs) && ((r_reg+r_grp)>ntop_refs) )
   {
      if (all_refs_page(r_reg, r_grp))
      {
         fprintf(out_fp,"<TR BGCOLOR=\"%s\">",GRPCOLOR);
         fprintf(out_fp,"<TD COLSPAN=4 ALIGN=\"center\">\n");
         fprintf(out_fp,"<FONT SIZE=\"-1\">");
         fprintf(out_fp,"<A HREF=\"./ref_%04d%02d.%s\">",
                 cur_year,cur_month,html_ext);
         fprintf(out_fp,"%s</A></TD></TR>\n",msg_v_refs);
      }
   }
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* ALL_REFS_PAGE - HTML page of all refs     */
/*********************************************/

int all_refs_page(u_int64_t r_reg, u_int64_t r_grp)
{
   RNODEPTR rptr, *pointer;
   char     ref_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(r_grp)?1:0;

   /* generate file name */
   snprintf(ref_fname,sizeof(ref_fname),"ref_%04d%02d.%s",
            cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(ref_fname))==NULL ) return 0;

   snprintf(buffer,sizeof(buffer),"%s %d - %s",
            l_month[cur_month-1],cur_year,msg_h_ref);
   write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %s\n",msg_h_hits,msg_h_ref);
   fprintf(out_fp,"----------------  --------------------\n\n");

   /* do groups first (if any) */
   pointer=r_array;
   while(r_grp)
   {
      rptr=*pointer++;
      if (rptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,"%-8llu %6.02f%%  %s\n",
            rptr->count,
            (t_hit==0)?0:((float)rptr->count/t_hit)*100.0,
            rptr->string);
         r_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   pointer=r_array;
   while(r_reg)
   {
      rptr=*pointer++;
      if (rptr->flag == OBJ_REG)
      {
         fprintf(out_fp,"%-8llu %6.02f%%  %s\n",
            rptr->count,
            (t_hit==0)?0:((float)rptr->count/t_hit)*100.0,
            rptr->string);
         r_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_AGENTS_TABLE - generate top n table   */
/*********************************************/

void top_agents_table()
{
   u_int64_t cnt, a_reg=0, a_grp=0, a_hid=0, tot_num;
   int       i;
   ANODEPTR  aptr, *pointer;

   if (t_agent == 0) return;    /* don't bother if we don't have any */

   cnt=a_ctr; pointer=a_array;
   while(cnt--)
   {
      /* calculate totals */
      switch ( (int)((ANODEPTR)(*pointer)->flag) )
      {
         case OBJ_REG:   a_reg++;  break;
         case OBJ_GRP:   a_grp++;  break;
         case OBJ_HIDE:  a_hid++;  break;
      }
      pointer++;
   }

   if ( (tot_num=a_reg+a_grp)==0 ) return;              /* split if none    */
   if (tot_num > ntop_agents) tot_num=ntop_agents;      /* get max to do... */

   fprintf(out_fp,"<A NAME=\"TOPAGENTS\"></A>\n");
   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=4>"        \
          "%s %llu %s %llu %s</TH></TR>\n",
          GREY, msg_top_top, tot_num, msg_top_of, t_agent, msg_top_a);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                  \
          "<FONT SIZE=\"-1\">#</FONT></TH>\n",
          GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"            \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",
          HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",
          MISCCOLOR,msg_h_agent);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   pointer=a_array; i=0;
   while(tot_num)
   {
      aptr=*pointer++;
      if (aptr->flag != OBJ_HIDE)
      {
         /* shade grouping? */
         if (shade_groups && (aptr->flag==OBJ_GRP))
            fprintf(out_fp,"<TR BGCOLOR=\"%s\">\n", GRPCOLOR);
         else fprintf(out_fp,"<TR>\n");

         fprintf(out_fp,
             "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n" \
             "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
             "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
             "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">",
             i+1,aptr->count,
             (t_hit==0)?0:((float)aptr->count/t_hit)*100.0);

         if ((aptr->flag==OBJ_GRP)&&hlite_groups)
            fprintf(out_fp,"<STRONG>%s</STRONG></FONT></TD></TR>\n",
               aptr->string);
         else fprintf(out_fp,"%s</FONT></TD></TR>\n",
               aptr->string);
         tot_num--;
         i++;
      }
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if ( (all_agents) && ((a_reg+a_grp)>ntop_agents) )
   {
      if (all_agents_page(a_reg, a_grp))
      {
         fprintf(out_fp,"<TR BGCOLOR=\"%s\">",GRPCOLOR);
         fprintf(out_fp,"<TD COLSPAN=4 ALIGN=\"center\">\n");
         fprintf(out_fp,"<FONT SIZE=\"-1\">");
         fprintf(out_fp,"<A HREF=\"./agent_%04d%02d.%s\">",
                 cur_year,cur_month,html_ext);
         fprintf(out_fp,"%s</A></TD></TR>\n",msg_v_agents);
      }
   }
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* ALL_AGENTS_PAGE - HTML user agent page    */
/*********************************************/

int all_agents_page(u_int64_t a_reg, u_int64_t a_grp)
{
   ANODEPTR aptr, *pointer;
   char     agent_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(a_grp)?1:0;

   /* generate file name */
   snprintf(agent_fname,sizeof(agent_fname),"agent_%04d%02d.%s",
            cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(agent_fname))==NULL ) return 0;

   snprintf(buffer,sizeof(buffer),"%s %d - %s",
            l_month[cur_month-1],cur_year,msg_h_agent);
   write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %s\n",msg_h_hits,msg_h_agent);
   fprintf(out_fp,"----------------  ----------------------\n\n");

   /* do groups first (if any) */
   pointer=a_array;
   while(a_grp)
   {
      aptr=*pointer++;
      if (aptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,"%-8llu %6.02f%%  %s\n",
             aptr->count,
             (t_hit==0)?0:((float)aptr->count/t_hit)*100.0,
             aptr->string);
         a_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   pointer=a_array;
   while(a_reg)
   {
      aptr=*pointer++;
      if (aptr->flag == OBJ_REG)
      {
         fprintf(out_fp,"%-8llu %6.02f%%  %s\n",
             aptr->count,
             (t_hit==0)?0:((float)aptr->count/t_hit)*100.0,
             aptr->string);
         a_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_SEARCH_TABLE - generate top n table   */
/*********************************************/

void top_search_table()
{
   u_int64_t cnt,t_val=0, tot_num;
   int       i;
   SNODEPTR  sptr, *pointer;

   if (a_ctr==0) return;                  /* don't bother if none to do    */

   cnt=tot_num=a_ctr; pointer=s_array;
   while(cnt--)
   {
      t_val+=(u_int64_t)(((SNODEPTR)(*pointer))->count);
      pointer++;
   }

   if ( tot_num > ntop_search) tot_num=ntop_search;

   fprintf(out_fp,"<A NAME=\"TOPSEARCH\"></A>\n");
   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=4>"        \
          "%s %llu %s %llu %s</TH></TR>\n",
          GREY, msg_top_top, tot_num, msg_top_of, a_ctr, msg_top_sr);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                  \
          "<FONT SIZE=\"-1\">#</FONT></TH>\n",
          GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"            \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",
          HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",
          MISCCOLOR,msg_h_search);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   pointer=s_array; i=0;
   while(tot_num)
   {
      sptr=*pointer++;
      fprintf(out_fp,
         "<TR>\n"                                                     \
         "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n" \
         "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
         "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
         "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">",
         i+1,sptr->count,
         (t_val==0)?0:((float)sptr->count/t_val)*100.0);
      fprintf(out_fp,"%s</FONT></TD></TR>\n",sptr->string);
      tot_num--;
      i++;
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if ( (all_search) && (a_ctr>ntop_search) )
   {
      if (all_search_page(a_ctr, t_val))
      {
         fprintf(out_fp,"<TR BGCOLOR=\"%s\">",GRPCOLOR);
         fprintf(out_fp,"<TD COLSPAN=4 ALIGN=\"center\">\n");
         fprintf(out_fp,"<FONT SIZE=\"-1\">");
         fprintf(out_fp,"<A HREF=\"./search_%04d%02d.%s\">",
                 cur_year,cur_month,html_ext);
         fprintf(out_fp,"%s</A></TD></TR>\n",msg_v_search);
      }
   }
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* ALL_SEARCH_PAGE - HTML for search strings */
/*********************************************/

int all_search_page(u_int64_t tot_num, u_int64_t t_val)
{
   SNODEPTR sptr, *pointer;
   char     search_fname[256], buffer[256];
   FILE     *out_fp;

   if (!tot_num) return 0;

   /* generate file name */
   snprintf(search_fname,sizeof(search_fname),"search_%04d%02d.%s",
            cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(search_fname))==NULL ) return 0;

   snprintf(buffer,sizeof(buffer),"%s %d - %s",
            l_month[cur_month-1],cur_year,msg_h_search);
   write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %s\n",msg_h_hits,msg_h_search);
   fprintf(out_fp,"----------------  ----------------------\n\n");

   pointer=s_array;
   while(tot_num)
   {
      sptr=*pointer++;
      fprintf(out_fp,"%-8llu %6.02f%%  %s\n",
         sptr->count,
         (t_val==0)?0:((float)sptr->count/t_val)*100.0,
         sptr->string);
      tot_num--;
   }
   fprintf(out_fp,"</PRE></FONT>\n");
   write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_USERS_TABLE - generate top n table    */
/*********************************************/

void top_users_table()
{
   u_int64_t cnt=0, i_reg=0, i_grp=0, i_hid=0, tot_num;
   int       i;
   INODEPTR  iptr, *pointer;

   cnt=a_ctr; pointer=i_array;
   while(cnt--)
   {
      /* calculate totals */
      switch ( (int)((INODEPTR)(*pointer)->flag) )
      {
         case OBJ_REG:   i_reg++;  break;
         case OBJ_GRP:   i_grp++;  break;
         case OBJ_HIDE:  i_hid++;  break;
      }
      pointer++;
   }

   if ( (tot_num=i_reg+i_grp)==0 ) return;              /* split if none    */
   if (tot_num > ntop_users) tot_num = ntop_users;

   fprintf(out_fp,"<A NAME=\"TOPUSERS\"></A>\n");       /* now do <A> tag   */

   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=10>" \
           "%s %llu %s %llu %s</TH></TR>\n",
           GREY,msg_top_top, tot_num, msg_top_of, t_user, msg_top_i);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                   \
          "<FONT SIZE=\"-1\">#</FONT></TH>\n",GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",FILECOLOR,msg_h_files);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",KBYTECOLOR,msg_h_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",VISITCOLOR,msg_h_visits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                       \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",MISCCOLOR,msg_h_uname);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   pointer=i_array; i=0;
   while(tot_num)
   {
      iptr=*pointer++;
      if (iptr->flag != OBJ_HIDE)
      {
         /* shade grouping? */
         if (shade_groups && (iptr->flag==OBJ_GRP))
            fprintf(out_fp,"<TR BGCOLOR=\"%s\">\n", GRPCOLOR);
         else fprintf(out_fp,"<TR>\n");

         fprintf(out_fp,
              "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n"  \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">",
              i+1,iptr->count,
              (t_hit==0)?0:((float)iptr->count/t_hit)*100.0,iptr->files,
              (t_file==0)?0:((float)iptr->files/t_file)*100.0,iptr->xfer/1024,
              (t_xfer==0)?0:((float)iptr->xfer/t_xfer)*100.0,iptr->visit,
              (t_visit==0)?0:((float)iptr->visit/t_visit)*100.0);

         if ((iptr->flag==OBJ_GRP)&&hlite_groups)
             fprintf(out_fp,"<STRONG>%s</STRONG></FONT></TD></TR>\n",
               iptr->string);
         else fprintf(out_fp,"%s</FONT></TD></TR>\n",
               iptr->string);
         tot_num--;
         i++;
      }
   }

   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if ( (all_users) && ((i_reg+i_grp)>ntop_users) )
   {
      if (all_users_page(i_reg, i_grp))
      {
         fprintf(out_fp,"<TR BGCOLOR=\"%s\">",GRPCOLOR);
         fprintf(out_fp,"<TD COLSPAN=10 ALIGN=\"center\">\n");
         fprintf(out_fp,"<FONT SIZE=\"-1\">");
         fprintf(out_fp,"<A HREF=\"./user_%04d%02d.%s\">",
            cur_year,cur_month,html_ext);
         fprintf(out_fp,"%s</A></TD></TR>\n",msg_v_users);
      }
   }
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* ALL_USERS_PAGE - HTML of all usernames    */
/*********************************************/

int all_users_page(u_int64_t i_reg, u_int64_t i_grp)
{
   INODEPTR iptr, *pointer;
   char     user_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(i_grp)?1:0;

   /* generate file name */
   snprintf(user_fname,sizeof(user_fname),"user_%04d%02d.%s",
            cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(user_fname))==NULL ) return 0;

   snprintf(buffer,sizeof(buffer),"%s %d - %s",
            l_month[cur_month-1],cur_year,msg_h_uname);
   write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %12s      %12s      %12s      %s\n",
           msg_h_hits, msg_h_files, msg_h_xfer, msg_h_visits, msg_h_uname);
   fprintf(out_fp,"----------------  ----------------  ----------------  " \
                  "----------------  --------------------\n\n");

   /* Do groups first (if any) */
   pointer=i_array;
   while(i_grp)
   {
      iptr=*pointer++;
      if (iptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,
      "%-8llu %6.02f%%  %8llu %6.02f%%  %8.0f %6.02f%%  %8llu %6.02f%%  %s\n",
            iptr->count,
            (t_hit==0)?0:((float)iptr->count/t_hit)*100.0,iptr->files,
            (t_file==0)?0:((float)iptr->files/t_file)*100.0,iptr->xfer/1024,
            (t_xfer==0)?0:((float)iptr->xfer/t_xfer)*100.0,iptr->visit,
            (t_visit==0)?0:((float)iptr->visit/t_visit)*100.0,
            iptr->string);
         i_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   /* Now do individual users (if any) */
   pointer=i_array;
   while(i_reg)
   {
      iptr=*pointer++;
      if (iptr->flag == OBJ_REG)
      {
         fprintf(out_fp,
      "%-8llu %6.02f%%  %8llu %6.02f%%  %8.0f %6.02f%%  %8llu %6.02f%%  %s\n",
            iptr->count,
            (t_hit==0)?0:((float)iptr->count/t_hit)*100.0,iptr->files,
            (t_file==0)?0:((float)iptr->files/t_file)*100.0,iptr->xfer/1024,
            (t_xfer==0)?0:((float)iptr->xfer/t_xfer)*100.0,iptr->visit,
            (t_visit==0)?0:((float)iptr->visit/t_visit)*100.0,
            iptr->string);
         i_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_CTRY_TABLE - top countries table      */
/*********************************************/

void top_ctry_table()
{
   int       i,j,x,tot_num=0,tot_ctry=0;
   int       ctry_fnd=0;
   u_int64_t idx;
   HNODEPTR  hptr;
   char      *domain;
   u_int64_t pie_data[10];
   char      *pie_legend[10];
   char      pie_title[48];
   char      pie_fname[48];
   char      flag_buf[256];

   extern int ctry_graph;  /* include external flag */

#ifdef USE_GEOIP
   extern int    geoip;
   extern GeoIP  *geo_fp;
   const  char   *geo_rc=NULL;
#endif
   char          geo_ctry[3]="--";

   /* scan hash table adding up domain totals */
   for (i=0;i<MAXHASH;i++)
   {
      hptr=sm_htab[i];
      while (hptr!=NULL)
      {
         if (hptr->flag != OBJ_GRP)   /* ignore group totals */
         {
            if (isipaddr(hptr->string)>0)
            {
               idx=0;                 /* unresolved/unknown  */
#ifdef USE_DNS
               if (geodb)
               {
                  /* Lookup IP address here, turn into idx   */
                  geodb_get_cc(geo_db, hptr->string, geo_ctry);
                  if (geo_ctry[0]=='-')
                  {
                     if (debug_mode)
                        fprintf(stderr,"GeoDB: %s unknown!\n",hptr->string);
                  }
                  else idx=ctry_idx(geo_ctry);
               }
#endif
#ifdef USE_GEOIP
               if (geoip)
               {
                  /* Lookup IP address here,  turn into idx  */
                  geo_rc=GeoIP_country_code_by_addr(geo_fp, hptr->string);
                  if (geo_rc==NULL||geo_rc[0]=='\0'||geo_rc[0]=='-')
                  {
                     if (debug_mode)
                        fprintf(stderr,"GeoIP: %s unknown (returns '%s')\n",
                                hptr->string,(geo_rc==NULL)?"null":geo_rc);
                  }
                  else
                  {
                     /* index returned geo_ctry */
                     geo_ctry[0]=tolower(geo_rc[0]);
                     geo_ctry[1]=tolower(geo_rc[1]);
                     idx=ctry_idx(geo_ctry);
                  }
               }
#endif /* USE_GEOIP */
            }
            else
            {
               /* resolved hostname.. try to get TLD */
               domain = hptr->string+strlen(hptr->string)-1;
               while ( (*domain!='.')&&(domain!=hptr->string)) domain--;
               if (domain++==hptr->string) idx=0;
               else idx=ctry_idx(domain);
            }
            if (idx!=0)
            {
               ctry_fnd=0;
               for (j=0;ctry[j].desc;j++)
               {
                  if (idx==ctry[j].idx)
                  {
                     ctry[j].count+=hptr->count;
                     ctry[j].files+=hptr->files;
                     ctry[j].xfer +=hptr->xfer;
                     ctry_fnd=1;
                     break;
                  }
               }
            }
            if (!ctry_fnd || idx==0)
            {
               ctry[0].count+=hptr->count;
               ctry[0].files+=hptr->files;
               ctry[0].xfer +=hptr->xfer;
            }
         }
         hptr=hptr->next;
      }
   }

   for (i=0;ctry[i].desc;i++)
   {
      if (ctry[i].count!=0) tot_ctry++;
      for (j=0;j<ntop_ctrys;j++)
      {
         if (top_ctrys[j]==NULL) { top_ctrys[j]=&ctry[i]; break; }
         else
         {
            if (ctry[i].count > top_ctrys[j]->count)
            {
               for (x=ntop_ctrys-1;x>j;x--)
                  top_ctrys[x]=top_ctrys[x-1];
               top_ctrys[x]=&ctry[i];
               break;
            }
         }
      }
   }

   /* put our anchor tag first... */
   fprintf(out_fp,"<A NAME=\"TOPCTRYS\"></A>\n");

   /* generate pie chart if needed */
   if (ctry_graph)
   {
      for (i=0;i<10;i++) pie_data[i]=0;             /* init data array      */
      if (ntop_ctrys<10) j=ntop_ctrys; else j=10;   /* ensure data size     */

      for (i=0;i<j;i++)
      {
         pie_data[i]=top_ctrys[i]->count;           /* load the array       */
         pie_legend[i]=top_ctrys[i]->desc;
      }
      snprintf(pie_title,sizeof(pie_title),"%s %s %d",
               msg_ctry_use,l_month[cur_month-1],cur_year);
      sprintf(pie_fname,"ctry_usage_%04d%02d.png",cur_year,cur_month);

      pie_chart(pie_fname,pie_title,t_hit,pie_data,pie_legend);  /* do it   */

      /* put the image tag in the page */
      fprintf(out_fp,"<IMG SRC=\"%s\" ALT=\"%s\" " \
                  "HEIGHT=300 WIDTH=512><P>\n",pie_fname,pie_title);
   }

   /* Now do the table */

   for (i=0;i<ntop_ctrys;i++) if (top_ctrys[i]->count!=0) tot_num++;
   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=8>"         \
           "%s %d %s %d %s</TH></TR>\n",
           GREY,msg_top_top,tot_num,msg_top_of,tot_ctry,msg_top_c);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                   \
          "<FONT SIZE=\"-1\">#</FONT></TH>\n",GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",FILECOLOR,msg_h_files);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",KBYTECOLOR,msg_h_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                       \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",MISCCOLOR,msg_h_ctry);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   for (i=0;i<ntop_ctrys;i++)
   {
      flag_buf[0]=0;
      if (use_flags)
      {
         domain=un_idx((idx=top_ctrys[i]->idx));
         if (strlen(domain)<3 && idx!=0) /* only to ccTLDs */
         {
            if ( domain[0]!='a'||domain[1]!='p' )  /* all but 'ap' */
            snprintf(flag_buf,sizeof(flag_buf),
            "<IMG SRC=\"%s/%s.png\" ALT=\"%s\" WIDTH=18 HEIGHT=12> ",
            flag_dir,domain,top_ctrys[i]->desc);
         }
      }

      if (top_ctrys[i]->count!=0)
      fprintf(out_fp,"<TR>"                                                \
              "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%llu</B></FONT></TD>\n"\
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n"\
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
              "<TD ALIGN=left NOWRAP>%s<FONT SIZE=\"-1\">%s</FONT>"        \
              "</TD></TR>\n",
              i+1,top_ctrys[i]->count,
              (t_hit==0)?0:((float)top_ctrys[i]->count/t_hit)*100.0,
              top_ctrys[i]->files,
              (t_file==0)?0:((float)top_ctrys[i]->files/t_file)*100.0,
              top_ctrys[i]->xfer/1024,
              (t_xfer==0)?0:((float)top_ctrys[i]->xfer/t_xfer)*100.0,
              flag_buf,top_ctrys[i]->desc);
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* DUMP_ALL_SITES - dump sites to tab file   */
/*********************************************/

void dump_all_sites()
{
   HNODEPTR  hptr, *pointer;
   FILE      *out_fp;
   char      filename[256];
   u_int64_t cnt=a_ctr;

   /* generate file name */
   snprintf(filename,sizeof(filename),"%s/site_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\t%s\t%s\t%s\n",
       msg_h_hits,msg_h_files,msg_h_xfer,msg_h_visits,msg_h_hname); 
   }

   /* dump 'em */
   pointer=h_array;
   while (cnt)
   {
      hptr=*pointer++;
      if (hptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,
         "%llu\t%llu\t%.0f\t%llu\t%s\n",
            hptr->count,hptr->files,hptr->xfer/1024,
            hptr->visit,hptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_URLS - dump all urls to tab file */
/*********************************************/

void dump_all_urls()
{
   UNODEPTR  uptr, *pointer;
   FILE      *out_fp;
   char      filename[256];
   u_int64_t cnt=a_ctr;

   /* generate file name */
   snprintf(filename,sizeof(filename),"%s/url_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\t%s\n",msg_h_hits,msg_h_xfer,msg_h_url);
   }

   /* dump 'em */
   pointer=u_array;
   while (cnt)
   {
      uptr=*pointer++;
      if (uptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,"%llu\t%.0f\t%s\n",
            uptr->count,uptr->xfer/1024,uptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_REFS - dump all refs to tab file */
/*********************************************/

void dump_all_refs()
{
   RNODEPTR  rptr, *pointer;
   FILE      *out_fp;
   char      filename[256];
   u_int64_t cnt=a_ctr;

   /* generate file name */
   snprintf(filename,sizeof(filename),"%s/ref_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\n",msg_h_hits,msg_h_ref);
   }

   /* dump 'em */
   pointer=r_array;
   while(cnt)
   {
      rptr=*pointer++;
      if (rptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,"%llu\t%s\n",rptr->count, rptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_AGENTS - dump agents htab file   */
/*********************************************/

void dump_all_agents()
{
   ANODEPTR  aptr, *pointer;
   FILE      *out_fp;
   char      filename[256];
   u_int64_t cnt=a_ctr;

   /* generate file name */
   snprintf(filename,sizeof(filename),"%s/agent_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\n",msg_h_hits,msg_h_agent);
   }

   /* dump 'em */
   pointer=a_array;
   while(cnt)
   {
      aptr=*pointer++;
      if (aptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,"%llu\t%s\n",aptr->count,aptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_USERS - dump username tab file   */
/*********************************************/

void dump_all_users()
{
   INODEPTR  iptr, *pointer;
   FILE      *out_fp;
   char      filename[256];
   u_int64_t cnt=a_ctr;

   /* generate file name */
   snprintf(filename,sizeof(filename),"%s/user_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\t%s\t%s\t%s\n",
         msg_h_hits,msg_h_files,msg_h_xfer,msg_h_visits,msg_h_uname);
   }

   /* dump 'em */
   pointer=i_array;
   while(cnt)
   {
      iptr=*pointer++;
      if (iptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,
         "%llu\t%llu\t%.0f\t%llu\t%s\n",
            iptr->count,iptr->files,iptr->xfer/1024,
            iptr->visit,iptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_SEARCH - dump search htab file   */
/*********************************************/

void dump_all_search()
{
   SNODEPTR  sptr, *pointer;
   FILE      *out_fp;
   char      filename[256];
   u_int64_t cnt=a_ctr;

   /* generate file name */
   snprintf(filename,sizeof(filename),"%s/search_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\n",msg_h_hits,msg_h_search);
   }

   /* dump 'em */
   pointer=s_array;
   while(cnt)
   {
      sptr=*pointer++;
      fprintf(out_fp,"%llu\t%s\n",sptr->count,sptr->string);
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* WRITE_MAIN_INDEX - main index.html file   */
/*********************************************/

int write_main_index()
{
   /* create main index file */

   int     i,j,days_in_month;
   int     s_year=hist[HISTSIZE-1].year;
   char    index_fname[256];
   char    buffer[BUFSIZE];
   u_int64_t m_hit=0;
   u_int64_t m_files=0;
   u_int64_t m_pages=0;
   u_int64_t m_visits=0;
   double    m_xfer=0.0;
   double  gt_hit=0.0;
   double  gt_files=0.0;
   double  gt_pages=0.0;
   double  gt_xfer=0.0;
   double  gt_visits=0.0;

   if (verbose>1) printf("%s\n",msg_gen_sum);

   snprintf(buffer,sizeof(buffer),"%s %s",msg_main_us,hname);
   year_graph6x("usage.png", buffer, hist);

   /* now do html stuff... */
   snprintf(index_fname,sizeof(index_fname),"index.%s",html_ext);

   /* .htaccess file needed? */
   if (htaccess)
   {
      if ((out_fp=fopen(".htaccess","wx")) != NULL)
      {
         fprintf(out_fp,"DirectoryIndex %s\n",index_fname);
         fclose(out_fp);
      }
      else
      {
         if (errno!=EEXIST && verbose)
            fprintf(stderr,"Error: Failed to create .htaccess file: %s\n",
                    strerror(errno));
      }
   }

   if ( (out_fp=open_out_file(index_fname)) == NULL)
   {
      if (verbose)
      fprintf(stderr,"%s %s!\n",msg_no_open,index_fname);
      return 1;
   }
   write_html_head(NULL, out_fp);

   /* year graph */
   fprintf(out_fp,"<IMG SRC=\"usage.png\" ALT=\"%s\" "    \
                  "HEIGHT=256 WIDTH=512><P>\n",buffer);
   /* month table */
   fprintf(out_fp,"<TABLE WIDTH=600 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH COLSPAN=11 BGCOLOR=\"%s\" ALIGN=center>",GREY);
   fprintf(out_fp,"%s</TH></TR>\n",msg_main_sum);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH ALIGN=left ROWSPAN=2 BGCOLOR=\"%s\">"          \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_h_mth);
   fprintf(out_fp,"<TH ALIGN=center COLSPAN=4 BGCOLOR=\"%s\">"            \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_main_da);
   fprintf(out_fp,"<TH ALIGN=center COLSPAN=6 BGCOLOR=\"%s\">"            \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",GREY,msg_main_mt);
   fprintf(out_fp,"<TR><TH ALIGN=center BGCOLOR=\"%s\">"                  \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",FILECOLOR,msg_h_files);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",PAGECOLOR,msg_h_pages);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",VISITCOLOR,msg_h_visits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",SITECOLOR,msg_h_sites);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",KBYTECOLOR,msg_h_xfer);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",VISITCOLOR,msg_h_visits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",PAGECOLOR,msg_h_pages);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",FILECOLOR,msg_h_files);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",HITCOLOR,msg_h_hits);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   for (i=HISTSIZE-1;i>=HISTSIZE-index_mths;i--)
   {
      if (hist[i].hit==0)
      {
         days_in_month=1;
         for (j=i;j>=0;j--) if (hist[j].hit!=0) break;
         if (j<0) break;
      }
      else days_in_month=(hist[i].lday-hist[i].fday)+1;

      /* Check for year change */
      if (s_year!=hist[i].year)
      {
         /* Year Totals */
         if (index_mths>16 && year_totals)
         {
            fprintf(out_fp,"<TR><TH COLSPAN=6 BGCOLOR=\"%s\" "         \
                "ALIGN=left><FONT SIZE=\"-1\"><STRONG>%04d</TH>\n",
                GRPCOLOR,s_year);
            fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                  "<FONT SIZE=\"-1\">%.0f</TH>", GRPCOLOR, m_xfer);
            fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                  "<FONT SIZE=\"-1\">%0llu</TH>", GRPCOLOR, m_visits);
            fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                  "<FONT SIZE=\"-1\">%0llu</TH>", GRPCOLOR, m_pages);
            fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                  "<FONT SIZE=\"-1\">%0llu</TH>", GRPCOLOR, m_files);
            fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                  "<FONT SIZE=\"-1\">%0llu</TH>", GRPCOLOR, m_hit);
            m_xfer=0; m_visits=0; m_pages=0; m_files=0; m_hit=0;
         }
 
         /* Year Header */
         s_year=hist[i].year;
         if (index_mths>16 && year_hdrs)
            fprintf(out_fp,"<TR><TH COLSPAN=11 BGCOLOR=\"%s\" "           \
               "ALIGN=center>%04d</TH></TR>\n", GREY, s_year);
      }

      fprintf(out_fp,"<TR><TD NOWRAP>");
      if (hist[i].hit!=0)
         fprintf(out_fp,"<A HREF=\"usage_%04d%02d.%s\">"                  \
                        "<FONT SIZE=\"-1\">%s %d</FONT></A></TD>\n",
                         hist[i].year, hist[i].month, html_ext,
                         s_month[hist[i].month-1], hist[i].year);
      else
         fprintf(out_fp,"<FONT SIZE=\"-1\">%s %d</FONT></A></TD>\n",      \
                         s_month[hist[i].month-1], hist[i].year);
                     
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>\n",
                      hist[i].hit/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>\n",
                      hist[i].files/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>\n",
                      hist[i].page/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>\n",
                      hist[i].visit/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>\n",
                      hist[i].site);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%.0f</FONT></TD>\n",
                      hist[i].xfer);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>\n",
                      hist[i].visit);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>\n",
                      hist[i].page);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>\n",
                      hist[i].files);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%llu</FONT></TD>",
                      hist[i].hit);
      fprintf(out_fp,"</TR>\n");
      gt_hit   += hist[i].hit;
      gt_files += hist[i].files;
      gt_pages += hist[i].page;
      gt_xfer  += hist[i].xfer;
      gt_visits+= hist[i].visit;
       m_hit   += hist[i].hit;
       m_files += hist[i].files;
       m_pages += hist[i].page;
       m_visits+= hist[i].visit;
       m_xfer  += hist[i].xfer;
   }

   if (index_mths>16 && year_totals)
   {
      fprintf(out_fp,"<TR><TH COLSPAN=6 BGCOLOR=\"%s\" "         \
                     "ALIGN=left><FONT SIZE=\"-1\"><STRONG>%04d</TH>\n",
                     GRPCOLOR,s_year);
      fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                     "<FONT SIZE=\"-1\">%.0f</TH>", GRPCOLOR, m_xfer);
      fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                     "<FONT SIZE=\"-1\">%0llu</TH>", GRPCOLOR, m_visits);
      fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                     "<FONT SIZE=\"-1\">%0llu</TH>", GRPCOLOR, m_pages);
      fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                     "<FONT SIZE=\"-1\">%0llu</TH>", GRPCOLOR, m_files);
      fprintf(out_fp,"<TH ALIGN=\"right\" BGCOLOR=\"%s\">"       \
                     "<FONT SIZE=\"-1\">%0llu</TH>", GRPCOLOR, m_hit);
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" COLSPAN=6 ALIGN=left>"          \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_h_totals);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_visits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_pages);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_files);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH></TR>\n",GREY,gt_hit);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"</TABLE>\n");
   write_html_tail(out_fp);
   fclose(out_fp);
   return 0;
}

/*********************************************/
/* QS_SITE_CMPH - QSort compare site by hits */
/*********************************************/

int qs_site_cmph(const void *cp1, const void *cp2)
{
   u_int64_t t1, t2;
   t1=(*(HNODEPTR *)cp1)->count;
   t2=(*(HNODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by hostname instead */
   return strcmp( (*(HNODEPTR *)cp1)->string,
                  (*(HNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_SITE_CMPK - QSort cmp site by bytes    */
/*********************************************/

int qs_site_cmpk(const void *cp1, const void *cp2)
{
   double t1, t2;
   t1=(*(HNODEPTR *)cp1)->xfer;
   t2=(*(HNODEPTR *)cp2)->xfer;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if xfer bytes are the same, we sort by hostname instead */
   return strcmp( (*(HNODEPTR *)cp1)->string,
                  (*(HNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_URL_CMPH - QSort compare URL by hits   */
/*********************************************/

int qs_url_cmph(const void *cp1, const void *cp2)
{
   u_int64_t t1, t2;
   t1=(*(UNODEPTR *)cp1)->count;
   t2=(*(UNODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by url instead */
   return strcmp( (*(UNODEPTR *)cp1)->string,
                  (*(UNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_URL_CMPK - QSort compare URL by bytes  */
/*********************************************/

int qs_url_cmpk(const void *cp1, const void *cp2)
{
   double t1, t2;
   t1=(*(UNODEPTR *)cp1)->xfer;
   t2=(*(UNODEPTR *)cp2)->xfer;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if xfer bytes are the same, we sort by url instead */
   return strcmp( (*(UNODEPTR *)cp1)->string,
                  (*(UNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_URL_CMPN - QSort compare URL by entry  */
/*********************************************/

int qs_url_cmpn(const void *cp1, const void *cp2)
{
   double t1, t2;
   t1=(*(UNODEPTR *)cp1)->entry;
   t2=(*(UNODEPTR *)cp2)->entry;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if xfer bytes are the same, we sort by url instead */
   return strcmp( (*(UNODEPTR *)cp1)->string,
                  (*(UNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_URL_CMPX - QSort compare URL by exit   */
/*********************************************/

int qs_url_cmpx(const void *cp1, const void *cp2)
{
   double t1, t2;
   t1=(*(UNODEPTR *)cp1)->exit;
   t2=(*(UNODEPTR *)cp2)->exit;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if xfer bytes are the same, we sort by url instead */
   return strcmp( (*(UNODEPTR *)cp1)->string,
                  (*(UNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_REF_CMPH - QSort compare Refs by hits  */
/*********************************************/

int qs_ref_cmph(const void *cp1, const void *cp2)
{
   u_int64_t t1, t2;
   t1=(*(RNODEPTR *)cp1)->count;
   t2=(*(RNODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by referrer URL instead */
   return strcmp( (*(RNODEPTR *)cp1)->string,
                  (*(RNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_AGNT_CMPH - QSort cmp Agents by hits   */
/*********************************************/

int qs_agnt_cmph(const void *cp1, const void *cp2)
{
   u_int64_t t1, t2;
   t1=(*(ANODEPTR *)cp1)->count;
   t2=(*(ANODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by agent string instead */
   return strcmp( (*(ANODEPTR *)cp1)->string,
                  (*(ANODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_SRCH_CMPH - QSort cmp srch str by hits */
/*********************************************/

int qs_srch_cmph(const void *cp1, const void *cp2)
{
   u_int64_t t1, t2;
   t1=(*(SNODEPTR *)cp1)->count;
   t2=(*(SNODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by search string instead */
   return strcmp( (*(SNODEPTR *)cp1)->string,
                  (*(SNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_IDENT_CMPH - QSort cmp ident by hits   */
/*********************************************/

int qs_ident_cmph(const void *cp1, const void *cp2)
{
   u_int64_t t1, t2;
   t1=(*(INODEPTR *)cp1)->count;
   t2=(*(INODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, sort by ident (username) string instead */
   return strcmp( (*(INODEPTR *)cp1)->string,
                  (*(INODEPTR *)cp2)->string );
}

/*********************************************/
/* LOAD_SITE_ARRAY - load up the sort array  */
/*********************************************/

u_int64_t load_site_array(HNODEPTR *pointer)
{
   HNODEPTR  hptr;
   int       i;
   u_int64_t ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      hptr=sm_htab[i];
      while (hptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=hptr;     /* otherwise, really do the load  */
         hptr=hptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_URL_ARRAY - load up the sort array   */
/*********************************************/

u_int64_t load_url_array(UNODEPTR *pointer)
{
   UNODEPTR  uptr;
   int       i;
   u_int64_t ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      uptr=um_htab[i];
      while (uptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=uptr;     /* otherwise, really do the load  */
         uptr=uptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_REF_ARRAY - load up the sort array   */
/*********************************************/

u_int64_t load_ref_array(RNODEPTR *pointer)
{
   RNODEPTR  rptr;
   int       i;
   u_int64_t ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      rptr=rm_htab[i];
      while (rptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=rptr;     /* otherwise, really do the load  */
         rptr=rptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_AGENT_ARRAY - load up the sort array */
/*********************************************/

u_int64_t load_agent_array(ANODEPTR *pointer)
{
   ANODEPTR  aptr;
   int       i;
   u_int64_t ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      aptr=am_htab[i];
      while (aptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=aptr;     /* otherwise, really do the load  */
         aptr=aptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_SRCH_ARRAY - load up the sort array  */
/*********************************************/

u_int64_t load_srch_array(SNODEPTR *pointer)
{
   SNODEPTR  sptr;
   int       i;
   u_int64_t ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      sptr=sr_htab[i];
      while (sptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=sptr;     /* otherwise, really do the load  */
         sptr=sptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_IDENT_ARRAY - load up the sort array */
/*********************************************/

u_int64_t load_ident_array(INODEPTR *pointer)
{
   INODEPTR  iptr;
   int       i;
   u_int64_t ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      iptr=im_htab[i];
      while (iptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=iptr;     /* otherwise, really do the load  */
         iptr=iptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* OPEN_OUT_FILE - Open file for output      */
/*********************************************/

FILE *open_out_file(char *filename)
{
   struct stat out_stat;
   FILE *out_fp;

   /* stat the file */
   if ( !(lstat(filename, &out_stat)) )
   {
      /* check if the file a symlink */
      if ( S_ISLNK(out_stat.st_mode) )
      {
         if (verbose)
         fprintf(stderr,"%s %s (symlink)\n",msg_no_open,filename);
         return NULL;
      }
   }

   /* open the file... */
   if ( (out_fp=fopen(filename,"w")) == NULL)
   {
      if (verbose)
      fprintf(stderr,"%s %s!\n",msg_no_open,filename);
      return NULL;
   }
   return out_fp;
}

