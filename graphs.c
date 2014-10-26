/*
    graphs.c  - produces graphs used by the Webalizer

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

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <gd.h>
#include <gdfontt.h>
#include <gdfonts.h>
#include <gdfontmb.h>

/* need socket header? */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "webalizer.h"
#include "preserve.h"
#include "lang.h"
#include "graphs.h"

/* Some systems don't define this */
#ifndef PI
#define PI 3.14159265358979323846
#endif

#define HITCOLOR   hit_or_green            /* graph color - hits  */
#define FILECOLOR  file_or_blue            /* files               */
#define SITECOLOR  site_or_orange          /* sites               */
#define KBYTECOLOR kbyte_or_red            /* KBytes              */
#define PAGECOLOR  page_or_cyan            /* Files               */
#define VISITCOLOR visit_or_yellow         /* Visits              */

/* shortcuts to convert ASCII hex color for gdImageColorAllocate() */

#define getred(s) (ashex2int((s[0] == '#')?s+1:s))
/* returns the red base-10 integer value from a html color */

#define getgreen(s) (ashex2int((s[0] == '#')?s+3:s+2))
/* returns the green base-10 integer value from a html color */

#define getblue(s) (ashex2int((s[0] == '#')?s+5:s+4))
/* returns the blue base-10 integer value from a html color */

#define CX 156                             /* center x (for pie)  */
#define CY 150                             /* center y  (chart)   */
#define XRAD 240                           /* X-axis radius       */
#define YRAD 200                           /* Y-axis radius       */

/* forward reference internal routines */

void    init_graph(char *, int, int);
struct  pie_data *calc_arc(float, float);
int     ashex2int(char *);

/* common public declarations */

char *numchar[] = { " 0"," 1"," 2"," 3"," 4"," 5"," 6"," 7"," 8"," 9","10",
                    "11","12","13","14","15","16","17","18","19","20",
                    "21","22","23","24","25","26","27","28","29","30","31"};

gdImagePtr      im;                        /* image buffer        */
FILE            *out;                      /* output file for PNG */
struct stat     out_stat;                  /* stat struct for PNG */
char            maxvaltxt[32];             /* graph values        */
float           percent;                   /* percent storage     */
u_int64_t       julday;                    /* julday value        */

struct pie_data { int x; int y;            /* line x,y            */
                  int mx; int my; };       /* midpoint x,y        */
/* colors */
int             black, white, grey, dkgrey, kbyte_or_red,
                file_or_blue, site_or_orange, hit_or_green,
                page_or_cyan, visit_or_yellow, blue;

/*****************************************************************/
/*                                                               */
/* YEAR_GRAPH6x  - Year graph from array of hist_rec structs     */
/*                                                               */
/*****************************************************************/

int year_graph6x(char *fname, char *title, struct hist_rec data[HISTSIZE])
{

   /* local variables */
   int i,j,x1,y1,x2;
   int s_mth,s_year=0;
   float cw,cs,co,ci;

   u_int64_t  maxval=1;
   double     fmaxval=0.0;

   /* initalize the graph */
   init_graph(title,512,256);              /* init as 512 x 256  */

   gdImageLine(im, 305,25,305,233,black);  /* draw section lines */
   gdImageLine(im, 304,25,304,233,white);
   gdImageLine(im, 305,130,490,130,black);
   gdImageLine(im, 305,129,490,129,white);

   /* index lines? */
   if (graph_lines)
   {
      y1=210/(graph_lines+1);
      for (i=0;i<graph_lines;i++)
       gdImageLine(im,21,((i+1)*y1)+25,303,((i+1)*y1)+25,dkgrey);
      y1=105/(graph_lines+1);
      for (i=0;i<graph_lines;i++)
       gdImageLine(im,306,((i+1)*y1)+25,489,((i+1)*y1)+25,dkgrey);
      for (i=0;i<graph_lines;i++)
       gdImageLine(im,306,((i+1)*y1)+130,489,((i+1)*y1)+130,dkgrey);
   }

   /* color coded legends? */
   if (graph_legend)
   {
      /* Kbytes Legend */
      i = (strlen(msg_h_xfer)*6);
      gdImageString(im,gdFontSmall,491-i,237,
                    (unsigned char *)msg_h_xfer,dkgrey);
      gdImageString(im,gdFontSmall,490-i,236,
                    (unsigned char *)msg_h_xfer,KBYTECOLOR);

      /* Sites/Visits Legend */
      i = (strlen(msg_h_visits)*6);
      j = (strlen(msg_h_sites)*6);
      gdImageString(im,gdFontSmall,491-i-j-12,11,
                    (unsigned char *)msg_h_visits,dkgrey);
      gdImageString(im,gdFontSmall,490-i-j-12,10,
                    (unsigned char *)msg_h_visits,VISITCOLOR);
      gdImageString(im,gdFontSmall,491-j-9,11,(unsigned char *)"/",dkgrey);
      gdImageString(im,gdFontSmall,490-j-9,10,(unsigned char *)"/",black);
      gdImageString(im,gdFontSmall,491-j,11,
                    (unsigned char *)msg_h_sites,dkgrey);
      gdImageString(im,gdFontSmall,490-j,10,
                    (unsigned char *)msg_h_sites,SITECOLOR);

      /* Hits/Files/Pages Legend */
      i = (strlen(msg_h_pages)*6);
      j = (strlen(msg_h_files)*6);
      gdImageStringUp(im,gdFontSmall,6,231,
                      (unsigned char *)msg_h_pages,dkgrey);
      gdImageStringUp(im,gdFontSmall,5,230,
                      (unsigned char *)msg_h_pages,PAGECOLOR);
      gdImageStringUp(im,gdFontSmall,6,231-i-3,(unsigned char *)"/",dkgrey);
      gdImageStringUp(im,gdFontSmall,5,230-i-3,(unsigned char *)"/",black);
      gdImageStringUp(im,gdFontSmall,6,231-i-12,
                      (unsigned char *)msg_h_files,dkgrey);
      gdImageStringUp(im,gdFontSmall,5,230-i-12,
                      (unsigned char *)msg_h_files,FILECOLOR);
      gdImageStringUp(im,gdFontSmall,6,231-i-j-15,(unsigned char *)"/",dkgrey);
      gdImageStringUp(im,gdFontSmall,5,230-i-j-15,(unsigned char *)"/",black);
      gdImageStringUp(im,gdFontSmall,6,231-i-j-24,
                      (unsigned char *)msg_h_hits,dkgrey);
      gdImageStringUp(im,gdFontSmall,5,230-i-j-24,
                      (unsigned char *)msg_h_hits,HITCOLOR);
   }

   /* Now draw data areas */
   s_mth = HISTSIZE-graph_mths;
   cs = 280.0/graph_mths; cw = cs/2;
   co = (48/graph_mths<1)?1:48/graph_mths;
   ci = 22+((cw-co)/2);

   /* x-axis legend */
   for (i=s_mth;i<HISTSIZE;i++)
   {
      if (graph_mths<16)
      {
         gdImageString(im,gdFontSmall,ci+((i-s_mth)*cs)+(((cw+co+co)-18)/2)+1,
                     236,(unsigned char *)s_month[data[i].month-1],black);
      }
      else if (graph_mths<36)
      {
         gdImageChar(im,gdFontSmall,ci+((i-s_mth)*cs)+(((cw+co+co)-6)/2)+1,
                     236,s_month[data[i].month-1][0],
                     (data[i].month==1)?blue:black);
      }
      else
      {
         if (s_year!=data[i].year)  /* year change only */
         {
            if (data[i].month==1 && (i-s_mth)!=0)
               gdImageChar(im,gdFontSmall, ci+((i-s_mth)*cs)-3,236,'|',blue);
            j=(12-data[i].month+1)*cs;
            if ((HISTSIZE-i)*cs < j) j=(HISTSIZE-i)*cs;
            if (j>28)
            {
               /* format the year string */
               sprintf(maxvaltxt, "%04d", data[i].year);
               gdImageString(im,gdFontSmall,ci+((i-s_mth)*cs)+(j/2)-12,
                             236, (unsigned char *)maxvaltxt, black);
            }
            s_year=data[i].year;
         }
      }

      if (data[i].hit   > maxval) maxval = data[i].hit;
      if (data[i].files > maxval) maxval = data[i].files;
      if (data[i].page  > maxval) maxval = data[i].page;
   }
   if (maxval <= 0) maxval = 1;
   sprintf(maxvaltxt, "%llu", maxval);
   gdImageStringUp(im,gdFontSmall,6,26+(strlen(maxvaltxt)*6),
                   (unsigned char *)maxvaltxt,black);

   /* hits */
   for (i=s_mth; i<HISTSIZE; i++)
   {
      percent = ((float)data[i].hit / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = ci + ((i-s_mth)*cs);
      x2 = x1 + cw;
      y1 = 232 - (percent * 203);
      gdImageFilledRectangle(im, x1, y1, x2, 232, HITCOLOR);
      if (cw>2) gdImageRectangle(im, x1, y1, x2, 232, black);
   }

   /* files */
   for (i=s_mth; i<HISTSIZE; i++)
   {
      percent = ((float)data[i].files / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = ci + co + ((i-s_mth)*cs);
      x2 = x1 + cw;
      y1 = 232 - (percent * 203);
      gdImageFilledRectangle(im, x1, y1, x2, 232, FILECOLOR);
      if (cw>2) gdImageRectangle(im, x1, y1, x2, 232, black);
   }

   /* pages */
   for (i=s_mth; i<HISTSIZE; i++)
   {
      percent = ((float)data[i].page / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = ci + co + co + ((i-s_mth)*cs);
      x2 = x1 + cw;
      y1 = 232 - (percent * 203);
      gdImageFilledRectangle(im, x1, y1, x2, 232, PAGECOLOR);
      if (cw>2) gdImageRectangle(im, x1, y1, x2, 232, black);
   }

   maxval=0;
   for (i=s_mth; i<HISTSIZE; i++)
   {
       if (data[i].site  > maxval) maxval = data[i].site;
       if (data[i].visit > maxval) maxval = data[i].visit;
   }
   if (maxval <= 0) maxval = 1;
   sprintf(maxvaltxt, "%llu", maxval);
   gdImageStringUp(im, gdFontSmall,493,26+(strlen(maxvaltxt)*6),
                   (unsigned char *)maxvaltxt, black);

   cs = 180.0/graph_mths; cw = cs/2;
   co = (48/graph_mths<1)?1:48/graph_mths;
   ci = 308+((cw-co)/2);

   /* visits */
   for (i=s_mth; i<HISTSIZE; i++)
   {
      percent = ((float)data[i].visit / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = ci + ((i-s_mth)*cs);
      x2 = x1 + cw;
      y1 = 127 - (percent * 98);
      gdImageFilledRectangle(im, x1, y1, x2, 127, VISITCOLOR);
      if (cw>2) gdImageRectangle(im, x1, y1, x2, 127, black);
   }

   /* sites */
   for (i=s_mth; i<HISTSIZE; i++)
   {
      percent = ((float)data[i].site / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = ci + co + ((i-s_mth)*cs);
      x2 = x1 + cw;
      y1 = 127 - (percent * 98);
      gdImageFilledRectangle(im, x1, y1, x2, 127, SITECOLOR);
      if (cw>2) gdImageRectangle(im, x1, y1, x2, 127, black);
   }

   fmaxval=0.0;
   for (i=s_mth; i<HISTSIZE; i++)
       if (data[i].xfer > fmaxval) fmaxval = data[i].xfer;
   if (fmaxval <= 0.0) fmaxval = 1.0;
   sprintf(maxvaltxt, "%.0f", fmaxval);
   gdImageStringUp(im, gdFontSmall,493,130+(strlen(maxvaltxt)*6),
                   (unsigned char *)maxvaltxt,black);

   cs = 180.0/graph_mths; cw = (cs/2)+(co/2);
   ci = 308+((cw-co)/2);

   /* xfer */
   for (i=s_mth; i<HISTSIZE; i++)
   {
      percent = ((float)data[i].xfer / (float)fmaxval);
      if (percent <= 0.0) continue;
      x1 = ci+ ((i-s_mth)*cs);
      x2 = x1 + cw;
      y1 = 232 - (percent * 98);
      gdImageFilledRectangle(im, x1, y1, x2, 232, KBYTECOLOR);
      if (cw>2) gdImageRectangle(im, x1, y1, x2, 232, black);
   }

   /* stat the file */
   if ( !(lstat(fname, &out_stat)) )
   {
      /* check if the file a symlink */
      if ( S_ISLNK(out_stat.st_mode) )
      {
         if (verbose)
         fprintf(stderr,"%s %s (symlink)\n",msg_no_open,fname);
         return(EBADF);
      }
   }

   /* save PNG image */
   if ((out = fopen(fname, "wb")) != NULL)
   {
      gdImagePng(im, out);
      fclose(out);
   }
   /* deallocate memory */
   gdImageDestroy(im);

   return (0);
}

/*****************************************************************/
/*                                                               */
/* MONTH_GRAPH6  - Month graph with six data sets                */
/*                                                               */
/*****************************************************************/

#define YSIZE 400

int month_graph6(     char  *fname,        /* filename           */
                      char  *title,        /* graph title        */
                      int   month,         /* graph month        */
                      int   year,          /* graph year         */
                 u_int64_t  data1[31],     /* data1 (hits)       */
                 u_int64_t  data2[31],     /* data2 (files)      */
                 u_int64_t  data3[31],     /* data3 (sites)      */
                 double     data4[31],     /* data4 (kbytes)     */
                 u_int64_t  data5[31],     /* data5 (views)      */
                 u_int64_t  data6[31])     /* data6 (visits)     */
{

   /* local variables */
   int         i,j,s,x1,y1,x2;
   u_int64_t   maxval=0;
   double      fmaxval=0.0;

   /* calc julian date for month */
   julday = (jdate(1, month,year) % 7);

   /* initalize the graph */
   init_graph(title,512,400);

   gdImageLine(im, 21, 180, 490, 180, black); /* draw section lines */
   gdImageLine(im, 21, 179, 490, 179, white);
   gdImageLine(im, 21, 280, 490, 280, black);
   gdImageLine(im, 21, 279, 490, 279, white);

   /* index lines? */
   if (graph_lines)
   {
      y1=154/(graph_lines+1);
      for (i=0;i<graph_lines;i++)
       gdImageLine(im,21,((i+1)*y1)+25,489,((i+1)*y1)+25,dkgrey);
      y1=100/(graph_lines+1);
      for (i=0;i<graph_lines;i++)
       gdImageLine(im,21,((i+1)*y1)+180,489,((i+1)*y1)+180,dkgrey);
      for (i=0;i<graph_lines;i++)
       gdImageLine(im,21,((i+1)*y1)+280,489,((i+1)*y1)+280,dkgrey);
   }

   /* x-axis legend */
   for (i=0;i<31;i++)
   {
      if ((julday % 7 == 6) || (julday % 7 == 0))
       gdImageString(im,gdFontSmall,25+(i*15),382,
                     (unsigned char *)numchar[i+1],HITCOLOR);
      else
       gdImageString(im,gdFontSmall,25+(i*15),382,
                     (unsigned char *)numchar[i+1],black);
      julday++;
   }

   /* y-axis legend */
   for (i=0; i<31; i++)
   {
       if (data1[i] > maxval) maxval = data1[i];           /* get max val    */
       if (data2[i] > maxval) maxval = data2[i];
       if (data5[i] > maxval) maxval = data5[i];
   }
   if (maxval <= 0) maxval = 1;
   sprintf(maxvaltxt, "%llu", maxval);
   gdImageStringUp(im, gdFontSmall,8,26+(strlen(maxvaltxt)*6),
                   (unsigned char *)maxvaltxt,black);

   if (graph_legend)                           /* Print color coded legends? */
   {
      /* Kbytes Legend */
      gdImageStringUp(im,gdFontSmall,494,376,
                      (unsigned char *)msg_h_xfer,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,375,
                      (unsigned char *)msg_h_xfer,KBYTECOLOR);

      /* Sites/Visits Legend */
      i = (strlen(msg_h_sites)*6);
      gdImageStringUp(im,gdFontSmall,494,276,
                      (unsigned char *)msg_h_sites,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,275,
                      (unsigned char *)msg_h_sites,SITECOLOR);
      gdImageStringUp(im,gdFontSmall,494,276-i-3,(unsigned char *)"/",dkgrey);
      gdImageStringUp(im,gdFontSmall,493,275-i-3,(unsigned char *)"/",black);
      gdImageStringUp(im,gdFontSmall,494,276-i-12,
                      (unsigned char *)msg_h_visits,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,275-i-12,
                      (unsigned char *)msg_h_visits,VISITCOLOR);

      /* Pages/Files/Hits Legend */
      s = ( i=(strlen(msg_h_pages)*6) )+
          ( j=(strlen(msg_h_files)*6) )+
          ( strlen(msg_h_hits)*6 )+ 52;
      gdImageStringUp(im,gdFontSmall,494,s,
                      (unsigned char *)msg_h_pages,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-1,
                      (unsigned char *)msg_h_pages,PAGECOLOR);
      gdImageStringUp(im,gdFontSmall,494,s-i-3,(unsigned char *)"/",dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-i-4,(unsigned char *)"/",black);
      gdImageStringUp(im,gdFontSmall,494,s-i-12,
                      (unsigned char *)msg_h_files,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-i-13,
                      (unsigned char *)msg_h_files,FILECOLOR);
      gdImageStringUp(im,gdFontSmall,494,s-i-j-15,(unsigned char *)"/",dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-i-j-16,(unsigned char *)"/",black);
      gdImageStringUp(im,gdFontSmall,494,s-i-j-24,
                      (unsigned char *)msg_h_hits,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-i-j-25,
                      (unsigned char *)msg_h_hits,HITCOLOR);
   }

   /* data1 */
   for (i=0; i<31; i++)
   {
      percent = ((float)data1[i] / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = 25 + (i*15);
      x2 = x1 + 7;
      y1 = 176 - (percent * 147);
      gdImageFilledRectangle(im, x1, y1, x2, 176, HITCOLOR);
      gdImageRectangle(im, x1, y1, x2, 176, black);
   }

   /* data2 */
   for (i=0; i<31; i++)
   {
      percent = ((float)data2[i] / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = 27 + (i*15);
      x2 = x1 + 7;
      y1 = 176 - (percent * 147);
      gdImageFilledRectangle(im, x1, y1, x2, 176, FILECOLOR);
      gdImageRectangle(im, x1, y1, x2, 176, black);
   }

   /* data5 */
   for (i=0; i<31; i++)
   {
      if (data5[i]==0) continue;
      percent = ((float)data5[i] / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = 29 + (i*15);
      x2 = x1 + 7;
      y1 = 176 - (percent * 147);
      gdImageFilledRectangle(im, x1, y1, x2, 176, PAGECOLOR);
      gdImageRectangle(im, x1, y1, x2, 176, black);
   }

   /* sites / visits */
   maxval=0;
   for (i=0; i<31; i++)
   {
      if (data3[i]>maxval) maxval = data3[i];
      if (data6[i]>maxval) maxval = data6[i];
   }
   if (maxval <= 0) maxval = 1;
   sprintf(maxvaltxt, "%llu", maxval);
   gdImageStringUp(im, gdFontSmall,8,180+(strlen(maxvaltxt)*6),
                   (unsigned char *)maxvaltxt, black);
   
   /* data 6 */
   for (i=0; i<31; i++)
   {
      percent = ((float)data6[i] / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = 25 + (i*15);
      x2 = x1 + 8;
      y1 = 276 - (percent * 92);
      gdImageFilledRectangle(im, x1, y1, x2, 276, VISITCOLOR);
      gdImageRectangle(im, x1, y1, x2, 276, black);
   }

   /* data 3 */
   for (i=0; i<31; i++)
   {
      percent = ((float)data3[i] / (float)maxval);
      if (percent <= 0.0) continue;
      x1 = 29 + (i*15);
      x2 = x1 + 7;
      y1 = 276 - (percent * 92);
      gdImageFilledRectangle(im, x1, y1, x2, 276, SITECOLOR);
      gdImageRectangle(im, x1, y1, x2, 276, black);
   }

   /* data4 */
   fmaxval=0.0;
   for (i=0; i<31; i++)
      if (data4[i]>fmaxval) fmaxval = data4[i];
   if (fmaxval <= 0.0) fmaxval = 1.0;
   sprintf(maxvaltxt, "%.0f", fmaxval/1024);
   gdImageStringUp(im, gdFontSmall,8,280+(strlen(maxvaltxt)*6),
                   (unsigned char *)maxvaltxt, black);
   
   for (i=0; i<31; i++)
   {
      percent = data4[i] / fmaxval;
      if (percent <= 0.0) continue;
      x1 = 26 + (i*15);
      x2 = x1 + 10;
      y1 = 375 - ( percent * 91 );
      gdImageFilledRectangle(im, x1, y1, x2, 375, KBYTECOLOR);
      gdImageRectangle(im, x1, y1, x2, 375, black);
   }

   /* stat the file */
   if ( !(lstat(fname, &out_stat)) )
   {
      /* check if the file a symlink */
      if ( S_ISLNK(out_stat.st_mode) )
      {
         if (verbose)
         fprintf(stderr,"%s %s (symlink)\n",msg_no_open,fname);
         return(EBADF);
      }
   }

   /* save PNG image */
   if ((out = fopen(fname, "wb")) != NULL)
   {
      gdImagePng(im, out);
      fclose(out);
   }
   /* deallocate memory */
   gdImageDestroy(im);

   return (0);
}

/*****************************************************************/
/*                                                               */
/* DAY_GRAPH3  - Day graph with three data sets                  */
/*                                                               */
/*****************************************************************/

int day_graph3(     char  *fname,
                    char  *title,
               u_int64_t  data1[24],
               u_int64_t  data2[24],
               u_int64_t  data3[24])
{

   /* local variables */
   int       i,j,s,x1,y1,x2;
   u_int64_t maxval=0;

   /* initalize the graph */
   init_graph(title,512,256);

   /* index lines? */
   if (graph_lines)
   {
      y1=210/(graph_lines+1);
      for (i=0;i<graph_lines;i++)
       gdImageLine(im,21,((i+1)*y1)+25,489,((i+1)*y1)+25,dkgrey);
   }

   /* x-axis legend */
   for (i=0;i<24;i++)
   {
      gdImageString(im,gdFontSmall,33+(i*19),238,
                    (unsigned char *)numchar[i],black);
      if (data1[i] > maxval) maxval = data1[i];           /* get max val    */
      if (data2[i] > maxval) maxval = data2[i];
      if (data3[i] > maxval) maxval = data3[i];
   }
   if (maxval <= 0) maxval = 1;
   sprintf(maxvaltxt, "%llu", maxval);
   gdImageStringUp(im, gdFontSmall, 8, 26+(strlen(maxvaltxt)*6),
                   (unsigned char *)maxvaltxt, black);
   
   if (graph_legend)                          /* print color coded legends? */
   {
      /* Pages/Files/Hits Legend */
      s = ( i=(strlen(msg_h_pages)*6) )+
          ( j=(strlen(msg_h_files)*6) )+
          ( strlen(msg_h_hits)*6 )+ 52;
      gdImageStringUp(im,gdFontSmall,494,s,
                      (unsigned char *)msg_h_pages,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-1,
                      (unsigned char *)msg_h_pages,PAGECOLOR);
      gdImageStringUp(im,gdFontSmall,494,s-i-3,(unsigned char *)"/",dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-i-4,(unsigned char *)"/",black);
      gdImageStringUp(im,gdFontSmall,494,s-i-12,
                      (unsigned char *)msg_h_files,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-i-13,
                      (unsigned char *)msg_h_files,FILECOLOR);
      gdImageStringUp(im,gdFontSmall,494,s-i-j-15,(unsigned char *)"/",dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-i-j-16,(unsigned char *)"/",black);
      gdImageStringUp(im,gdFontSmall,494,s-i-j-24,
                      (unsigned char *)msg_h_hits,dkgrey);
      gdImageStringUp(im,gdFontSmall,493,s-i-j-25,
                      (unsigned char *)msg_h_hits,HITCOLOR);
   }

   /* data1 */
   for (i=0; i<24; i++)
   {
      percent = ((float)data1[i] / (float)maxval);  /* percent of 100% */
      if (percent <= 0.0) continue;
      x1 = 29 + (i*19);
      x2 = x1 + 10;
      y1 = 232 - (percent * 203);
      gdImageFilledRectangle(im, x1, y1, x2, 232, HITCOLOR);
      gdImageRectangle(im, x1, y1, x2, 232, black);
   }

   /* data2 */
   for (i=0; i<24; i++)
   {
      percent = ((float)data2[i] / (float)maxval);  /* percent of 100% */
      if (percent <= 0.0) continue;
      x1 = 32 + (i*19);
      x2 = x1 + 10;
      y1 = 232 - (percent * 203);
      gdImageFilledRectangle(im, x1, y1, x2, 232, FILECOLOR);
      gdImageRectangle(im, x1, y1, x2, 232, black);
   }

   /* data3 */
   for (i=0; i<24; i++)
   {
      percent = ((float)data3[i] / (float)maxval);  /* percent of 100% */
      if (percent <= 0.0) continue;
      x1 = 35 + (i*19);
      x2 = x1 + 10;
      y1 = 232 - (percent * 203);
      gdImageFilledRectangle(im, x1, y1, x2, 232, PAGECOLOR);
      gdImageRectangle(im, x1, y1, x2, 232, black);
   }

   /* stat the file */
   if ( !(lstat(fname, &out_stat)) )
   {
      /* check if the file a symlink */
      if ( S_ISLNK(out_stat.st_mode) )
      {
         if (verbose)
         fprintf(stderr,"%s %s (symlink)\n",msg_no_open,fname);
         return(EBADF);
      }
   }

   /* save PNG image */
   if ((out = fopen(fname, "wb")) != NULL)
   {
      gdImagePng(im, out);
      fclose(out);
   }
   /* deallocate memory */
   gdImageDestroy(im);

   return (0);
}

/*****************************************************************/
/*                                                               */
/* PIE_CHART  - draw a pie chart (10 data items max)             */
/*                                                               */
/*****************************************************************/

int pie_chart(char *fname, char *title, u_int64_t t_val,
              u_int64_t data1[], char *legend[])
{
   int i,x,percent,y=47;
   double s_arc=0.0;
   int purple_or_pie1, ltgreen_or_pie2, ltpurple_or_pie3, brown_or_pie4;
   int r, g, b;
   char buffer[128];

   struct pie_data gdata;

   /* init graph and colors */
   init_graph(title,512,300);
   r=getred(pie_color1); g=getgreen(pie_color1); b=getblue(pie_color1);
   purple_or_pie1  = gdImageColorAllocate(im, r, g, b);
   r=getred(pie_color2); g=getgreen(pie_color2); b=getblue(pie_color2);
   ltgreen_or_pie2 = gdImageColorAllocate(im, r, g, b);
   r=getred(pie_color3); g=getgreen(pie_color3); b=getblue(pie_color3);
   ltpurple_or_pie3= gdImageColorAllocate(im, r, g, b);
   r=getred(pie_color4); g=getgreen(pie_color4); b=getblue(pie_color4);
   brown_or_pie4 = gdImageColorAllocate(im, r, g, b);

   /* do the circle... */
   gdImageArc(im, CX, CY, XRAD, YRAD, 0, 360, black);
   gdImageArc(im, CX, CY+10, XRAD-2, YRAD-2, 2, 178, black);
   gdImageFillToBorder(im, CX, CY+(YRAD/2)+1, black, black);

   /* slice the pie */
   gdata=*calc_arc(0.0,0.0);
   gdImageLine(im,CX,CY,gdata.x,gdata.y,black);  /* inital line           */

   for (i=0;i<10;i++)                      /* run through data array      */
   {
      if ((data1[i]!=0)&&(s_arc<1.0))      /* make sure valid slice       */
      {
         percent=(((double)data1[i]/t_val)+0.005)*100.0;
         if (percent<1) break;

         if (s_arc+((double)percent/100.0)>=1.0)
         {
            gdata=*calc_arc(s_arc,1.0);
            s_arc=1.0;
         }
         else
         {
            gdata=*calc_arc(s_arc,s_arc+((double)percent/100.0));
            s_arc+=(double)percent/100.0;
         }

         gdImageLine(im, CX, CY, gdata.x, gdata.y, black);
         gdImageFill(im, gdata.mx, gdata.my, i+5);

	 snprintf(buffer,sizeof(buffer),"%s (%d%%)",legend[i], percent);
         x=480-(strlen(buffer)*7);
         gdImageString(im,gdFontMediumBold, x+1, y+1,
                       (unsigned char *)buffer, black);
         gdImageString(im,gdFontMediumBold, x, y,
                       (unsigned char *)buffer, i+5);
         y+=20;
      }
   }

   if (s_arc < 1.0)                         /* anything left over?        */
   {
      gdata=*calc_arc(s_arc,1.0);

      gdImageFill(im, gdata.mx, gdata.my, white);
      snprintf(buffer,sizeof(buffer),"%s (%d%%)",
           msg_h_other,100-(int)(s_arc*100));
      x=480-(strlen(buffer)*7);
      gdImageString(im,gdFontMediumBold, x+1, y+1,
                    (unsigned char *)buffer, black);
      gdImageString(im,gdFontMediumBold, x, y,
                    (unsigned char *)buffer, white);
   }

   /* stat the file */
   if ( !(lstat(fname, &out_stat)) )
   {
      /* check if the file a symlink */
      if ( S_ISLNK(out_stat.st_mode) )
      {
         if (verbose)
         fprintf(stderr,"%s %s (symlink)\n",msg_no_open,fname);
         return(EBADF);
      }
   }

   /* save PNG image */
   if ((out = fopen(fname, "wb")) != NULL)
   {
      gdImagePng(im, out);
      fclose(out);
   }
   /* deallocate memory */
   gdImageDestroy(im);

   return (0);
}

/*****************************************************************/
/*                                                               */
/* CALC_ARC  - generate x,y coordinates for pie chart            */
/*                                                               */
/*****************************************************************/

struct pie_data *calc_arc(float min, float max)
{
   static struct pie_data data;
   double d;

   /* Calculate max line */
   d=max;
   data.x=cos(d*(2*PI))*((XRAD-2)/2)+CX;
   data.y=sin(d*(2*PI))*((YRAD-2)/2)+CY;
   /* Now get mid-point  */
   d=((min+max)/2);
   data.mx=cos(d*(2*PI))*(XRAD/3)+CX;
   data.my=sin(d*(2*PI))*(YRAD/3)+CY;
   return &data;
}

/*****************************************************************/
/*                                                               */
/* INIT_GRAPH  - initalize graph and draw borders                */
/*                                                               */
/*****************************************************************/

void init_graph(char *title, int xsize, int ysize)
{
   int i, r, g, b;

   im = gdImageCreate(xsize,ysize);

   /* allocate color maps, background color first (grey) */
   grey    = gdImageColorAllocate(im, 192, 192, 192);
   dkgrey  = gdImageColorAllocate(im, 128, 128, 128);
   black   = gdImageColorAllocate(im, 0, 0, 0);
   white   = gdImageColorAllocate(im, 255, 255, 255);
   blue    = gdImageColorAllocate(im, 0, 0, 255);
   r=getred(hit_color); g=getgreen(hit_color); b=getblue(hit_color);
   hit_or_green = gdImageColorAllocate(im, r, g, b);
   r=getred(site_color); g=getgreen(site_color); b=getblue(site_color);
   site_or_orange = gdImageColorAllocate(im, r, g, b);
   r=getred(file_color); g=getgreen(file_color); b=getblue(file_color);
   file_or_blue = gdImageColorAllocate(im, r, g, b);
   r=getred(kbyte_color); g=getgreen(kbyte_color); b=getblue(kbyte_color);
   kbyte_or_red = gdImageColorAllocate(im, r, g, b);
   r=getred(page_color); g=getgreen(page_color); b=getblue(page_color);
   page_or_cyan = gdImageColorAllocate(im, r, g, b);
   r=getred(visit_color); g=getgreen(visit_color); b=getblue(visit_color);
   visit_or_yellow = gdImageColorAllocate(im, r, g, b);

   /* black outside border */
   gdImageRectangle(im, 0, 0, xsize-1, ysize-1, black);

   /* do shadow effect (bevel) border */
   for (i=1; i<5 ;i++)
   {
      gdImageLine(im, i, i, xsize-i-2, i, white);
      gdImageLine(im, i, i, i, ysize-i-2, white);
      gdImageLine(im, i+1, ysize-i-1, xsize-i-1, ysize-i-1, dkgrey);
      gdImageLine(im, xsize-i-1, i+1, xsize-i-1, ysize-i-1, dkgrey);
   }

   /* generic inside shadow box */
   gdImageRectangle(im, 20, 25, xsize-21, ysize-21, black);
   gdImageRectangle(im, 19, 24, xsize-22, ysize-22, white);

   /* display the graph title */
   gdImageString(im, gdFontMediumBold, 20, 8,
                 (unsigned char *)title, blue);

   return;
}

/****************************************************************/
/*                                                              */
/* ASHEX2INT - ASCII HEX TO INT CONVERTER                       */
/*                                                              */
/****************************************************************/

int ashex2int(char *str)
{
   /* returns base-10 integer value from a 2 ASCII hex number   */
   return from_hex(str[1])+(from_hex(str[0])*16);
}
