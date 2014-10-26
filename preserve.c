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

#include "webalizer.h"                        /* main header              */
#include "lang.h"
#include "hashtab.h"
#include "parser.h"
#include "preserve.h"

struct hist_rec hist[HISTSIZE];              /* history structure array   */

/*********************************************/
/* GET_HISTORY - load in history file        */
/*********************************************/

void get_history()
{
   int   i,n,numfields;
   int   in_m,in_y;
   int   mth, yr;
   FILE  *hist_fp;
   char  buffer[BUFSIZE];

   /* try to open history file */
   hist_fp=fopen(hist_fname,"r");

   if (hist_fp)
   {
      if (verbose>1) printf("%s %s\n",msg_get_hist,hist_fname);
      while ( fgets(buffer,BUFSIZE,hist_fp) != NULL )
      {
         if (buffer[0]=='#') { continue; } /* skip comments */

         /* get record month/year */
         sscanf(buffer,"%d %d",&in_m,&in_y);

         /* check if valid numbers */
         if ( (in_m<1 || in_m>12 || in_y<1970) )
         {
            if (verbose) fprintf(stderr,"%s (mth=%d)\n",msg_bad_hist,in_m);
            continue;
         }

         /* populate if first time through */
         if (hist[HISTSIZE-1].year==0) populate_history(in_m, in_y);

         for (i=HISTSIZE-1;i>=0;i--)
         {
            if (in_m==hist[i].month && in_y==hist[i].year) break;
            else
            {
               if ( (in_m>hist[i].month&&in_y==hist[i].year) ||
                    (in_y>hist[i].year) )
               {
                  if (i>0)
                  {
                     n=(mth_idx(in_m,in_y)-mth_idx(hist[i].month,hist[i].year));
                     while (n)
                     {
                        yr = hist[i].year;
                        mth= hist[i].month+1;
                        if (mth>12) { mth=1; yr++; }
                        memcpy(&hist[0], &hist[1], sizeof(hist[0])*i);
                        memset(&hist[i], 0, sizeof(struct hist_rec));
                        hist[i].year=yr; hist[i].month=mth; n--;
                    }
                  }
                  break;
               }
            }
         }
         if (i>=0)
         {
         /* month# year# requests files sites xfer firstday lastday */
         numfields = sscanf(buffer,"%d %d %llu %llu %llu %lf %d %d %llu %llu",
                       &hist[i].month,
                       &hist[i].year,
                       &hist[i].hit,
                       &hist[i].files,
                       &hist[i].site,
                       &hist[i].xfer,
                       &hist[i].fday,
                       &hist[i].lday,
                       &hist[i].page,
                       &hist[i].visit);
         }
      }
      fclose(hist_fp);
   }
   else if (verbose>1) printf("%s\n",msg_no_hist);
}

/*********************************************/
/* PUT_HISTORY - write out history file      */
/*********************************************/

void put_history()
{
   int     i;
   FILE    *hist_fp;
   char    new_fname[MAXKVAL+4];
   char    old_fname[MAXKVAL+4];
   struct  stat hist_stat;
   time_t  now;
   char    timestamp[48];

   /* generate 'new' filename */
   sprintf(new_fname, "%s.new", hist_fname);

   /* stat the file */
   if ( !(lstat(new_fname, &hist_stat)) )
   {
      /* check if the file a symlink */
      if ( S_ISLNK(hist_stat.st_mode) )
      {
         if (verbose)
         fprintf(stderr,"%s %s (symlink)\n",msg_no_open,new_fname);
         return;
      }
   }

   /* Generate our timestamp */
   now=time(NULL);
   strftime(timestamp,sizeof(timestamp),"%d/%b/%Y %H:%M:%S",localtime(&now));

   /* Open file for writing */
   hist_fp = fopen(new_fname,"w");
   if (hist_fp)
   {
      if (verbose>1) printf("%s\n",msg_put_hist);

      /* write header */
      fprintf(hist_fp,"# Webalizer V%s-%s History Data - %s (%d month)\n",
              version, editlvl, timestamp, HISTSIZE);

      for (i=HISTSIZE-1;i>=0;i--)
      {
         fprintf(hist_fp,"%d %d %llu %llu %llu %.0f %d %d %llu %llu\n",
                         hist[i].month,
                         hist[i].year,
                         hist[i].hit,
                         hist[i].files,
                         hist[i].site,
                         hist[i].xfer,
                         hist[i].fday,
                         hist[i].lday,
                         hist[i].page,
                         hist[i].visit);
      }
      /* Done, close file */
      fclose(hist_fp);

      /* if time-warp error detected, save old */
      if (hist_gap)
      {
         sprintf(old_fname, "%s.sav", hist_fname);
         if ((rename(hist_fname,old_fname)==-1)&&(errno!=ENOENT)&&verbose)
            fprintf(stderr,"Failed renaming %s to %s: %s\n",
               hist_fname,old_fname,strerror(errno));
      }

      /* now rename the 'new' file to real name */
      if ((rename(new_fname,hist_fname) == -1) && verbose)
         fprintf(stderr,"Failed renaming %s to %s\n",new_fname,hist_fname);
   }
   else
      if (verbose)
      fprintf(stderr,"%s %s\n",msg_hist_err,new_fname);
}

/*********************************************/
/* POPULATE_HISTORY - populate with dates    */
/*********************************************/

void populate_history(int month, int year)
{
   int   i;
   int   mth=month;
   int   yr =year;

   if (hist[HISTSIZE-1].year==0)
   {
      for (i=HISTSIZE-1;i>=0;i--)
      {
         hist[i].year=yr; hist[i].month=mth--;
         if (mth==0) { yr--; mth=12; }
      }
   }
}

/*********************************************/
/* UPDATE_HISTORY - update with cur totals   */
/*********************************************/

void update_history()
{
   int   i,n;
   int   mth,yr;

   /* populate if first time through */
   if (hist[HISTSIZE-1].year==0) populate_history(cur_month,cur_year);

   /* we need to figure out where to put in history */
   for (i=HISTSIZE-1;i>=0;i--)
   {
      if (cur_month==hist[i].month && cur_year==hist[i].year) break;
      else
      {
         if ((cur_month>hist[i].month&&cur_year==hist[i].year) ||
             (cur_year>hist[i].year))
         {
            if (i>0)
            {
               n=(mth_idx(cur_month,cur_year) -
                  mth_idx(hist[i].month,hist[i].year));

               if (n>2)
               {
                  if (verbose)
                     fprintf(stderr,"Warning! %d month gap detected! "   \
                             "(%d/%d to %d/%d)\n", n, hist[i].month,
                             hist[i].year, cur_month, cur_year);
                  if (n>11) hist_gap=1;  /* year or more? */
               }

               while (n)
               {
                  yr = hist[i].year;
                  mth= hist[i].month+1;
                  if (mth>12) { mth=1; yr++; }
                  memcpy(&hist[0],&hist[1],sizeof(hist[0])*i);
                  memset(&hist[i], 0, sizeof(struct hist_rec));
                  hist[i].year=yr; hist[i].month=mth; n--;
               }
            }
            break;
         }
      }
   }
   if (i>=0)
   {
      hist[i].month = cur_month;
      hist[i].year  = cur_year;
      hist[i].hit   = t_hit;
      hist[i].files = t_file;
      hist[i].page  = t_page;
      hist[i].visit = t_visit;
      hist[i].site  = t_site;
      hist[i].xfer  = t_xfer/1024;
      hist[i].fday  = f_day;
      hist[i].lday  = l_day;
   }
}

/*********************************************/
/* SAVE_STATE - save internal data structs   */
/*********************************************/

int save_state()
{
   HNODEPTR hptr;
   UNODEPTR uptr;
   RNODEPTR rptr;
   ANODEPTR aptr;
   SNODEPTR sptr;
   INODEPTR iptr;

   FILE *fp;
   int  i;
   struct stat state_stat;

   char buffer[BUFSIZE];
   char new_fname[MAXKVAL+4];

   /* generate 'new' filename */
   sprintf(new_fname, "%s.new", state_fname);

   /* stat the file */
   if ( !(lstat(new_fname, &state_stat)) )
   {
      /* check if the file a symlink */
      if ( S_ISLNK(state_stat.st_mode) )
      {
         if (verbose)
         fprintf(stderr,"%s %s (symlink)\n",msg_no_open,new_fname);
         return(EBADF);
      }
   }

   /* Open file for writing */
   fp=fopen(new_fname,"w");
   if (fp==NULL) return 1;

   /* Saving current run data... */
   if (verbose>1)
   {
      sprintf(buffer,"%02d/%02d/%04d %02d:%02d:%02d",
       cur_month,cur_day,cur_year,cur_hour,cur_min,cur_sec);
      printf("%s [%s]\n",msg_put_data,buffer);
   }

   /* first, save the easy stuff */
   /* Header record */
   snprintf(buffer,sizeof(buffer),
     "# Webalizer V%s-%s Incremental Data - %02d/%02d/%04d %02d:%02d:%02d\n",
      version,editlvl,cur_month,cur_day,cur_year,cur_hour,cur_min,cur_sec);
   if (fputs(buffer,fp)==EOF) return 1;  /* error exit */

   /* Current date/time          */
   sprintf(buffer,"%d %d %d %d %d %d\n",
        cur_year, cur_month, cur_day, cur_hour, cur_min, cur_sec);
   if (fputs(buffer,fp)==EOF) return 1;  /* error exit */

   /* Monthly totals for sites, urls, etc... */
   sprintf(buffer,"%llu %llu %llu %llu %llu %llu %.0f %llu %llu %llu\n",
        t_hit, t_file, t_site, t_url,
        t_ref, t_agent, t_xfer, t_page, t_visit, t_user);
   if (fputs(buffer,fp)==EOF) return 1;  /* error exit */

   /* Daily totals for sites, urls, etc... */
   sprintf(buffer,"%llu %llu %llu %d %d\n",
        dt_site, ht_hit, mh_hit, f_day, l_day);
   if (fputs(buffer,fp)==EOF) return 1;  /* error exit */

   /* Monthly (by day) total array */
   for (i=0;i<31;i++)
   {
      sprintf(buffer,"%llu %llu %.0f %llu %llu %llu\n",
        tm_hit[i],tm_file[i],tm_xfer[i],tm_site[i],tm_page[i],tm_visit[i]);
      if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
   }

   /* Daily (by hour) total array */
   for (i=0;i<24;i++)
   {
      sprintf(buffer,"%llu %llu %.0f %llu\n",
        th_hit[i],th_file[i],th_xfer[i],th_page[i]);
      if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
   }

   /* Response codes */
   for (i=0;i<TOTAL_RC;i++)
   {
      sprintf(buffer,"%llu\n",response[i].count);
      if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
   }

   /* now we need to save our linked lists */
   /* URL list */
   if (fputs("# -urls- \n",fp)==EOF) return 1;  /* error exit */
   for (i=0;i<MAXHASH;i++)
   {
      uptr=um_htab[i];
      while (uptr!=NULL)
      {
         snprintf(buffer,sizeof(buffer),"%s\n%d %llu %llu %.0f %llu %llu\n",
                  uptr->string, uptr->flag, uptr->count, uptr->files,
                  uptr->xfer, uptr->entry, uptr->exit);
         if (fputs(buffer,fp)==EOF) return 1;
         uptr=uptr->next;
      }
   }
   if (fputs("# End Of Table - urls\n",fp)==EOF) return 1;  /* error exit */

   /* daily hostname list */
   if (fputs("# -sites- (monthly)\n",fp)==EOF) return 1;  /* error exit */

   for (i=0;i<MAXHASH;i++)
   {
      hptr=sm_htab[i];
      while (hptr!=NULL)
      {
         snprintf(buffer,sizeof(buffer),"%s\n%d %llu %llu %.0f %llu %llu\n%s\n",
                  hptr->string, hptr->flag, hptr->count, hptr->files,
                  hptr->xfer, hptr->visit, hptr->tstamp,
                  (hptr->lasturl==blank_str)?"-":hptr->lasturl);
         if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
         hptr=hptr->next;
      }
   }
   if (fputs("# End Of Table - sites (monthly)\n",fp)==EOF) return 1;

   /* hourly hostname list */
   if (fputs("# -sites- (daily)\n",fp)==EOF) return 1;  /* error exit */
   for (i=0;i<MAXHASH;i++)
   {
      hptr=sd_htab[i];
      while (hptr!=NULL)
      {
         snprintf(buffer,sizeof(buffer),"%s\n%d %llu %llu %.0f %llu %llu\n%s\n",
                  hptr->string, hptr->flag, hptr->count, hptr->files,
                  hptr->xfer, hptr->visit, hptr->tstamp,
                  (hptr->lasturl==blank_str)?"-":hptr->lasturl);
         if (fputs(buffer,fp)==EOF) return 1;
         hptr=hptr->next;
      }
   }
   if (fputs("# End Of Table - sites (daily)\n",fp)==EOF) return 1;

   /* Referrer list */
   if (fputs("# -referrers- \n",fp)==EOF) return 1;  /* error exit */
   if (t_ref != 0)
   {
      for (i=0;i<MAXHASH;i++)
      {
         rptr=rm_htab[i];
         while (rptr!=NULL)
         {
            snprintf(buffer,sizeof(buffer),"%s\n%d %llu\n",
                     rptr->string, rptr->flag, rptr->count);
            if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
            rptr=rptr->next;
         }
      }
   }
   if (fputs("# End Of Table - referrers\n",fp)==EOF) return 1;

   /* User agent list */
   if (fputs("# -agents- \n",fp)==EOF) return 1;  /* error exit */
   if (t_agent != 0)
   {
      for (i=0;i<MAXHASH;i++)
      {
         aptr=am_htab[i];
         while (aptr!=NULL)
         {
            snprintf(buffer,sizeof(buffer),"%s\n%d %llu\n",
                     aptr->string, aptr->flag, aptr->count);
            if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
            aptr=aptr->next;
         }
      }
   }
   if (fputs("# End Of Table - agents\n",fp)==EOF) return 1;

   /* Search String list */
   if (fputs("# -search strings- \n",fp)==EOF) return 1;  /* error exit */
   for (i=0;i<MAXHASH;i++)
   {
      sptr=sr_htab[i];
      while (sptr!=NULL)
      {
         snprintf(buffer,sizeof(buffer),"%s\n%llu\n",
                  sptr->string,sptr->count);
         if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
         sptr=sptr->next;
      }
   }
   if (fputs("# End Of Table - search strings\n",fp)==EOF) return 1;

   /* username list */
   if (fputs("# -usernames- \n",fp)==EOF) return 1;  /* error exit */

   for (i=0;i<MAXHASH;i++)
   {
      iptr=im_htab[i];
      while (iptr!=NULL)
      {
         snprintf(buffer,sizeof(buffer),"%s\n%d %llu %llu %.0f %llu %llu\n",
                  iptr->string, iptr->flag, iptr->count, iptr->files,
              iptr->xfer, iptr->visit, iptr->tstamp);
         if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
         iptr=iptr->next;
      }
   }
   if (fputs("# End Of Table - usernames\n",fp)==EOF) return 1;

   /* Done, close file */
   fclose(fp);

   /* now rename the 'new' file to real name */
   if ((rename(new_fname,state_fname) == -1) && verbose)
   {
      fprintf(stderr,"Failed renaming %s to %s\n",new_fname,state_fname);
      return 1;         /* Failed, return with error code                */
   }
   return 0;            /* successful, return with good return code      */
}

/*********************************************/
/* RESTORE_STATE - reload internal run data  */
/*********************************************/

int restore_state()
{
   FILE *fp;
   int  i;
   struct hnode t_hnode;         /* Temporary hash nodes */
   struct unode t_unode;
   struct rnode t_rnode;
   struct anode t_anode;
   struct snode t_snode;
   struct inode t_inode;

   char         buffer[BUFSIZE];
   char         tmp_buf[BUFSIZE];

   u_int64_t    ul_bogus=0;

   /* if ignoring, just return */
   if (ignore_state) return 0;

   /* try to open state file */
   fp=fopen(state_fname,"r");
   if (fp==NULL)
   {
      /* Previous run data not found... */
      if (verbose>1) printf("%s\n",msg_no_data);
      return 0;   /* return with ok code */
   }

   /* Reading previous run data... */
   if (verbose>1) printf("%s %s\n",msg_get_data,state_fname);

   /* get easy stuff */
   sprintf(tmp_buf,"# Webalizer V%s    ",version);
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)                 /* Header record */
   {
      if (strncmp(buffer,tmp_buf,16))
      {
         /* Kludge to allow 2.01 files also */
         sprintf(tmp_buf,"# Webalizer V2.01-1");
         if (strncmp(buffer,tmp_buf,19)) return 99; /* bad magic? */
      }
   }
   else return 1;   /* error exit */

   /* Get current timestamp */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      sscanf(buffer,"%d %d %d %d %d %d",
       &cur_year, &cur_month, &cur_day,
       &cur_hour, &cur_min, &cur_sec);
   } else return 2;  /* error exit */

   /* calculate current timestamp (seconds since epoch) */
   cur_tstamp=((jdate(cur_day,cur_month,cur_year)-epoch)*86400)+
                     (cur_hour*3600)+(cur_min*60)+cur_sec;

   /* Get monthly totals */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      sscanf(buffer,"%llu %llu %llu %llu %llu %llu %lf %llu %llu %llu",
       &t_hit, &t_file, &t_site, &t_url,
       &t_ref, &t_agent, &t_xfer, &t_page, &t_visit, &t_user);
   } else return 3;  /* error exit */
     
   /* Get daily totals */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      sscanf(buffer,"%llu %llu %llu %d %d",
       &dt_site, &ht_hit, &mh_hit, &f_day, &l_day);
   } else return 4;  /* error exit */

   /* get daily totals */
   for (i=0;i<31;i++)
   {
      if ((fgets(buffer,BUFSIZE,fp)) != NULL)
      {
         sscanf(buffer,"%llu %llu %lf %llu %llu %llu",
          &tm_hit[i],&tm_file[i],&tm_xfer[i],&tm_site[i],&tm_page[i],
          &tm_visit[i]);
      } else return 5;  /* error exit */
   }

   /* get hourly totals */
   for (i=0;i<24;i++)
   {
      if ((fgets(buffer,BUFSIZE,fp)) != NULL)
      {
         sscanf(buffer,"%llu %llu %lf %llu",
          &th_hit[i],&th_file[i],&th_xfer[i],&th_page[i]);
      } else return 6;  /* error exit */
   }

   /* get response code totals */
   for (i=0;i<TOTAL_RC;i++)
   {
      if ((fgets(buffer,BUFSIZE,fp)) != NULL)
         sscanf(buffer,"%llu",&response[i].count);
      else return 7;  /* error exit */
   }

   /* Kludge for V2.01-06 TOTAL_RC off by one bug */
   if (!strncmp(buffer,"# -urls- ",9)) response[TOTAL_RC-1].count=0;
   else
   {
      /* now do hash tables */

      /* url table */
      if ((fgets(buffer,BUFSIZE,fp)) != NULL)            /* Table header */
      { if (strncmp(buffer,"# -urls- ",9)) return 10; }  /* (url)        */
      else return 10;   /* error exit */
   }

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXURLH);
      tmp_buf[strlen(tmp_buf)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 10;  /* error exit */
      if (!isdigit((unsigned char)buffer[0])) return 10;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %llu %llu %lf %llu %llu",
         &t_unode.flag,&t_unode.count,
         &t_unode.files, &t_unode.xfer,
         &t_unode.entry, &t_unode.exit);

      /* Good record, insert into hash table */
      if (put_unode(tmp_buf,t_unode.flag,t_unode.count,
         t_unode.xfer,&ul_bogus,t_unode.entry,t_unode.exit,um_htab))
      {
         if (verbose)
         /* Error adding URL node, skipping ... */
         fprintf(stderr,"%s %s\n", msg_nomem_u, t_unode.string);
      }
   }

   /* monthly sites table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -sites- ",10)) return 8; }    /* (monthly)    */
   else return 8;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      /* Check for end of table */
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXHOST);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 8;  /* error exit */
      if (!isdigit((unsigned char)buffer[0])) return 8;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %llu %llu %lf %llu %llu",
         &t_hnode.flag,&t_hnode.count,
         &t_hnode.files, &t_hnode.xfer,
         &t_hnode.visit, &t_hnode.tstamp);

      /* get last url */
      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 8;  /* error exit */
      if (buffer[0]=='-') t_hnode.lasturl=blank_str;
      else
      {
         buffer[strlen(buffer)-1]=0;
         t_hnode.lasturl=find_url(buffer);
      }

      /* Good record, insert into hash table */
      if (put_hnode(tmp_buf,t_hnode.flag,
         t_hnode.count,t_hnode.files,t_hnode.xfer,&ul_bogus,
         t_hnode.visit+1,t_hnode.tstamp,t_hnode.lasturl,sm_htab))
      {
         /* Error adding host node (monthly), skipping .... */
         if (verbose) fprintf(stderr,"%s %s\n",msg_nomem_mh, t_hnode.string);
      }
   }

   /* Daily sites table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -sites- ",10)) return 9; }    /* (daily)      */
   else return 9;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      /* Check for end of table */
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXHOST);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 9;  /* error exit */
      if (!isdigit((unsigned char)buffer[0])) return 9;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %llu %llu %lf %llu %llu",
          &t_hnode.flag,&t_hnode.count,
          &t_hnode.files, &t_hnode.xfer,
          &t_hnode.visit, &t_hnode.tstamp);

      /* get last url */
      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 9;  /* error exit */
      if (buffer[0]=='-') t_hnode.lasturl=blank_str;
      else
      {
         buffer[strlen(buffer)-1]=0;
         t_hnode.lasturl=find_url(buffer);
      }

      /* Good record, insert into hash table */
      if (put_hnode(tmp_buf,t_hnode.flag,
         t_hnode.count,t_hnode.files,t_hnode.xfer,&ul_bogus,
         t_hnode.visit+1,t_hnode.tstamp,t_hnode.lasturl,sd_htab))
      {
         /* Error adding host node (daily), skipping .... */
         if (verbose) fprintf(stderr,"%s %s\n",msg_nomem_dh, t_hnode.string);
      }
   }

   /* Referrers table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -referrers- ",14)) return 11; } /* (referrers)*/
   else return 11;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXREFH);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 11;  /* error exit */
      if (!isdigit((unsigned char)buffer[0])) return 11;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %llu",&t_rnode.flag,&t_rnode.count);

      /* insert node */
      if (put_rnode(tmp_buf,t_rnode.flag,
         t_rnode.count, &ul_bogus, rm_htab))
      {
         if (verbose) fprintf(stderr,"%s %s\n", msg_nomem_r, log_rec.refer);
      }
   }

   /* Agents table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -agents- ",11)) return 12; } /* (agents)*/
   else return 12;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXAGENT);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 12;  /* error exit */
      if (!isdigit((unsigned char)buffer[0])) return 12;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %llu",&t_anode.flag,&t_anode.count);

      /* insert node */
      if (put_anode(tmp_buf,t_anode.flag,t_anode.count,
         &ul_bogus,am_htab))
      {
         if (verbose) fprintf(stderr,"%s %s\n", msg_nomem_a, log_rec.agent);
      }
   }

   /* Search Strings table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -search string",16)) return 13; }  /* (search)*/
   else return 13;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXSRCH);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 13;  /* error exit */
      if (!isdigit((unsigned char)buffer[0])) return 13;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%llu",&t_snode.count);

      /* insert node */
      if (put_snode(tmp_buf,t_snode.count,sr_htab))
      {
         if (verbose) fprintf(stderr,"%s %s\n", msg_nomem_sc, t_snode.string);
      }
   }

   /* usernames table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -usernames- ",10)) return 14; }
   else return 14;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      /* Check for end of table */
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXIDENT);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 14;  /* error exit */
      if (!isdigit((unsigned char)buffer[0])) return 14;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %llu %llu %lf %llu %llu",
         &t_inode.flag,&t_inode.count,
         &t_inode.files, &t_inode.xfer,
         &t_inode.visit, &t_inode.tstamp);

      /* Good record, insert into hash table */
      if (put_inode(tmp_buf,t_inode.flag,
         t_inode.count,t_inode.files,t_inode.xfer,&ul_bogus,
         t_inode.visit+1,t_inode.tstamp,im_htab))
      {
         if (verbose)
         /* Error adding username node, skipping .... */
         fprintf(stderr,"%s %s\n",msg_nomem_i, t_inode.string);
      }
   }

   fclose(fp);
   check_dup = 1;              /* enable duplicate checking */
   return 0;                   /* return with ok code       */
}
