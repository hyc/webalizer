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
#include "parser.h"

/* internal function prototypes */
void fmt_logrec(char *);
int  parse_record_clf(char *);
int  parse_record_ftp(char *);
int  parse_record_squid(char *);
int  parse_record_w3c(char *);

/*********************************************/
/* FMT_LOGREC - terminate log fields w/zeros */
/*********************************************/

void fmt_logrec(char *buffer)
{
   char *cp=buffer;
   int  q=0,b=0,p=0;

   while (*cp != '\0')
   {
      /* break record up, terminate fields with '\0' */
      switch (*cp)
      {
       case '\t': if (b || q || p) break; *cp='\0';   break;
       case ' ': if (b || q || p) break; *cp='\0';    break;
       case '"': if (*(cp-1)=='\\') break; else q^=1; break;
       case '[': if (q) break; b++;                   break;
       case ']': if (q) break; if (b>0) b--;          break;
       case '(': if (q) break; p++;                   break;
       case ')': if (q) break; if (p>0) p--;          break;
      }
      cp++;
   }
}

/*********************************************/
/* PARSE_RECORD - uhhh, you know...          */
/*********************************************/

int parse_record(char *buffer)
{
   /* clear out structure */
   memset(&log_rec,0,sizeof(struct log_struct));

   /* call appropriate handler */
   switch (log_type)
   {
      default:
      case LOG_CLF:   return parse_record_clf(buffer);   break; /* clf   */
      case LOG_FTP:   return parse_record_ftp(buffer);   break; /* ftp   */
      case LOG_SQUID: return parse_record_squid(buffer); break; /* squid */
      case LOG_W3C:   return parse_record_w3c(buffer);   break; /* w3c   */
   }
}

/*********************************************/
/* PARSE_RECORD_FTP - ftp log handler        */
/*********************************************/

int parse_record_ftp(char *buffer)
{
   int size;
   int i,j,count;
   char *cp1, *cp2, *cpx, *cpy, *eob;

   size = strlen(buffer);                 /* get length of buffer        */
   eob = buffer+size;                     /* calculate end of buffer     */
   fmt_logrec(buffer);                    /* separate fields with \0's   */

   /* Start out with date/time       */
   cp1=buffer;
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0 && cp1<eob) cp1++;
   cpx=cp1;       /* save month name */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0 && cp1<eob) cp1++;
   i=atoi(cp1);   /* get day number  */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0 && cp1<eob) cp1++;
   cpy=cp1;       /* get timestamp   */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0 && cp1<eob) cp1++;
   j=atoi(cp1);   /* get year        */

   /* minimal sanity check */
   if (*(cpy+2)!=':' || *(cpy+5)!=':') return 0;
   if (j<1990 || j>2100) return 0;
   if (i<1 || i>31) return 0;

   /* format date/time field         */
   snprintf(log_rec.datetime,sizeof(log_rec.datetime),
            "[%02d/%s/%4d:%s -0000]",i,cpx,j,cpy);

   /* skip seconds... */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0 && cp1<eob) cp1++;
   while (*cp1!=0 && cp1<eob) cp1++;

   /* get hostname */
   if (*(cp1+1)==0)
   {
      /* Blank? That's weird.. */
      strcpy(log_rec.hostname,"NONE");
      if (debug_mode) fprintf(stderr, "Warning: Blank hostname found!\n");
   }
   else
   {
      /* good hostname */
      strncpy(log_rec.hostname, ++cp1, MAXHOST);
      log_rec.hostname[MAXHOST-1]=0;
      while (*cp1!=0 && cp1<eob) cp1++;
   }
   while (*cp1==0 && cp1<eob) cp1++;

   /* get filesize */
   if (*cp1<'0'||*cp1>'9') log_rec.xfer_size=0;
   else log_rec.xfer_size = strtoul(cp1,NULL,10);

   /* URL stuff */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0 && cp1<eob) cp1++;
   cpx=cp1;
   /* get next field for later */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0 && cp1<eob) cp1++;

   /* skip next two */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* fabricate an appropriate request string based on direction */
   if (*cp1=='i')
      snprintf(log_rec.url,sizeof(log_rec.url),"\"POST %s\"",cpx);
   else
      snprintf(log_rec.url,sizeof(log_rec.url),"\"GET %s\"",cpx);

   if (cp1<eob) cp1++;
   if (cp1<eob) cp1++;
   while (*cp1!=0 && cp1<eob) cp1++;
   if (cp1<eob) cp1++;
   cp2=log_rec.ident;count=MAXIDENT-1;
   while (*cp1!=0 && cp1<eob && count) { *cp2++ = *cp1++; count--; }
   *cp2='\0';

   /* return appropriate response code */
   log_rec.resp_code=(*(eob-2)=='i')?206:200;

   return 1;
}

/*********************************************/
/* PARSE_RECORD_CLF - CLF web log handler    */
/*********************************************/

int parse_record_clf(char *buffer)
{
   int size;
   char *cp1, *cp2, *cpx, *eob, *eos;

   size = strlen(buffer);                 /* get length of buffer        */
   eob = buffer+size;                     /* calculate end of buffer     */
   fmt_logrec(buffer);                    /* separate fields with \0's   */

   /* HOSTNAME */
   cp1 = cpx = buffer; cp2=log_rec.hostname;
   eos = (cp1+MAXHOST)-1;
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_host);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   /* skip next field (ident) */
   while ( (*cp1 != '\0') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;

   /* IDENT (authuser) field */
   cpx = cp1;
   cp2 = log_rec.ident;
   eos = (cp1+MAXIDENT-1);
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '[') && (cp1 < eos) ) /* remove embeded spaces */
   {
      if (*cp1=='\0') *cp1=' ';
      *cp2++=*cp1++;
   }
   *cp2--='\0';

   if (cp1 >= eob) return 0;

   /* check if oversized username */
   if (*cp1 != '[')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_user);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while ( (*cp1 != '[') && (cp1 < eob) ) cp1++;
   }

   /* strip trailing space(s) */
   while (*cp2==' ') *cp2--='\0';

   /* date/time string */
   cpx = cp1;
   cp2 = log_rec.datetime;
   eos = (cp1+28);
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_date);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   /* minimal sanity check on timestamp */
   if ( (log_rec.datetime[0] != '[') ||
        (log_rec.datetime[3] != '/') ||
        (cp1 >= eob))  return 0;

   /* HTTP request */
   cpx = cp1;
   cp2 = log_rec.url;
   eos = (cp1+MAXURL-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_req);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   if ( (log_rec.url[0] != '"') ||
        (cp1 >= eob) ) return 0;

   /* Strip off HTTP version from URL */
   if ( (cp2=strstr(log_rec.url,"HTTP"))!=NULL )
   {
      *cp2='\0';          /* Terminate string */
      *(--cp2)='"';       /* change <sp> to " */
   }

   /* response code */
   log_rec.resp_code = atoi(cp1);

   /* xfer size */
   while ( (*cp1 != '\0') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   if (*cp1<'0'||*cp1>'9') log_rec.xfer_size=0;
   else log_rec.xfer_size = strtoul(cp1,NULL,10);

   /* done with CLF record */
   if (cp1>=eob) return 1;

   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   /* get referrer if present */
   cpx = cp1;
   cp2 = log_rec.refer;
   eos = (cp1+MAXREF-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_ref);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   cpx = cp1;
   cp2 = log_rec.agent;
   eos = cp1+(MAXAGENT-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';

   return 1;     /* maybe a valid record, return with TRUE */
}

/*********************************************/
/* PARSE_RECORD_SQUID - squid log handler    */
/*********************************************/

int parse_record_squid(char *buffer)
{
   int size, slash_count=0;
   time_t i;
   char *cp1, *cp2, *cpx, *eob, *eos;

   size = strlen(buffer);                 /* get length of buffer        */
   eob = buffer+size;                     /* calculate end of buffer     */
   fmt_logrec(buffer);                    /* separate fields with \0's   */

   /* date/time */
   cp1=buffer;
   i=atoi(cp1);		/* get timestamp */

   /* format date/time field */
   strftime(log_rec.datetime,sizeof(log_rec.datetime),
            "[%d/%b/%Y:%H:%M:%S -0000]",localtime(&i));

   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* skip request size */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* HOSTNAME */
   cpx = cp1; cp2=log_rec.hostname;
   eos = (cp1+MAXHOST)-1;
   if (eos >= eob) eos=eob-1;

   while ((*cp1 != '\0') && (cp1 != eos)) *cp2++ = *cp1++;
   *cp2='\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_host);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   /* skip cache status */
   while (*cp1!=0 && cp1<eob && *cp1!='/') cp1++;
   cp1++;

   /* response code */
   log_rec.resp_code = atoi(cp1);
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* xfer size */
   if (*cp1<'0'||*cp1>'9') log_rec.xfer_size=0;
   else log_rec.xfer_size = strtoul(cp1,NULL,10);

   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* HTTP request type */
   cpx = cp1;
   cp2 = log_rec.url;
   *cp2++ = '\"';
   eos = (cp1+MAXURL-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_req);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   *cp2++ = ' ';

   /* HTTP URL requested */
   cpx = cp1;

   if (trimsquid>0)
   {
      slash_count=trimsquid+2;
      while ( (*cp1 != '\0') && (cp1 != eos) && slash_count)
      {
         *cp2++ = *cp1++;
         if (*cp1 == '/') slash_count--;
      }
   }
   else while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
 
   *cp2 = '\0';
   if ((*cp1 != '\0' && trimsquid==0) || (trimsquid && slash_count) )
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_req);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   *cp2++ = '\"';

   /* IDENT (authuser) field */
   cpx = cp1;
   cp2 = log_rec.ident;
   eos = (cp1+MAXIDENT-1);
   if (eos >= eob) eos=eob-1;

   while (*cp1 == ' ') cp1++; /* skip white space */

   while ( (*cp1 != ' ' && *cp1!='\0') && (cp1 < eos) )  *cp2++=*cp1++;

   *cp2--='\0';

   if (cp1 >= eob) return 0;

   /* strip trailing space(s) */
   while (*cp2==' ') *cp2--='\0';

   /* we have no interest in the remaining fields */
   return 1;
}

/*********************************************/
/* PARSE_RECORD_W3C - w3c log handler        */
/*********************************************/

/* field index structure */
struct  field_index_struct
{  
   int date;       /* Date field index                */
   int time;       /* Time field index                */
   int ip;         /* IP field index                  */
   int username;   /* Username field index            */
   int method;     /* Method field index              */
   int url;        /* URL field index                 */
   int query;      /* Querystring field index         */
   int status;     /* Status code field index         */
   int size;       /* Size field index                */
   int referer;    /* Referrer field index            */
   int agent;      /* User agent field index          */
   int fields;     /* Number of fields in this format */
};

/* field structure */
struct  fields_struct
{  
   char *date;     /* Date field       */
   char *time;     /* Time field       */
   char *ip;       /* IP field         */
   char *username; /* Username field   */
   char *method;   /* Method field     */
   char *url;      /* URL field        */
   char *query;    /* Querystring      */
   char *status;   /* Status code      */
   char *size;     /* Size field       */
   char *referer;  /* Referrer field   */
   char *agent;    /* User agent field */
};

int parse_record_w3c(char *buffer)
{
   int size;
   char *eob;
   char *cp;
   int index;
   static struct field_index_struct field_index;
   struct fields_struct fields;
   struct tm gm_time, *local_time;
   time_t timestamp;

   memset(&gm_time, 0, sizeof(struct tm));
   size = strlen(buffer);                 /* get length of buffer        */
   eob = buffer + size;                   /* calculate end of buffer     */

   /* remove line end markers, reduce eob accordingly */
   cp = eob;
   while(cp>buffer)
   {
      cp--;
      if (*cp == '\r' || *cp=='\n')
      {
         *cp = '\0';
         eob--;
      }
      else
         break;
   }

   fmt_logrec(buffer);                    /* separate fields with \0's   */

   cp = buffer;

   /* Check if the line is empty or a line suffers from the IIS 
      Null-Character bug and abort parsing if found. */
   if (*cp == '\0') return 0;

   /* If it's a header line ignore it or parse the Fields header if found */
   if (*cp == '#')
   {
      cp++;
      if (!strcmp(cp, "Fields:"))
      {
         /* Reset the field indices */
         memset(&field_index, 0, sizeof(struct field_index_struct));
         while (*cp) cp++;
         cp++;
         index = 1;
         while (cp < eob)
         {
            /* Set the field index */
            if (!strcmp(cp, "date"))           field_index.date     = index;
            if (!strcmp(cp, "time"))           field_index.time     = index;
            if (!strcmp(cp, "c-ip"))           field_index.ip       = index;
            if (!strcmp(cp, "cs-method"))      field_index.method   = index;
            if (!strcmp(cp, "cs-uri-stem"))    field_index.url      = index;
            if (!strcmp(cp, "cs-uri-query"))   field_index.query    = index;
            if (!strcmp(cp, "sc-status"))      field_index.status   = index;
            if (!strcmp(cp, "cs(Referer)"))    field_index.referer  = index;
            if (!strcmp(cp, "sc-bytes"))       field_index.size     = index;
            if (!strcmp(cp, "cs(User-Agent)")) field_index.agent    = index;
            if (!strcmp(cp, "cs-username"))    field_index.username = index;
            
            /* Continue with the next field */
            while (*cp) cp++;
            cp++;
            index++;
         }
         field_index.fields = index -1;
      }

      /* Return because this header line is completely parsed */
      return 0;
   }

   /* A data line has been found */

   /* Check if the number of entries in this line are conform to the
      format specified in the header */
   index = 1;
   while (cp < eob)
   {
      while (*cp) cp++;
      cp++;
      index++;
   }
   if (index-1 != field_index.fields) return 0;
   
   /* Reset pointer */
   cp = buffer;
   
   /* Reset the field pointers and begin parsing the data line */
   memset(&fields, 0, sizeof(struct fields_struct));
   index = 1;
   while (cp < eob)
   {
      /* Set the field pointers */
      if (index == field_index.date)     fields.date      = cp;
      if (index == field_index.time)     fields.time      = cp;
      if (index == field_index.ip)       fields.ip        = cp;
      if (index == field_index.method)   fields.method    = cp;
      if (index == field_index.url)      fields.url       = cp;
      if (index == field_index.query)    fields.query     = cp;
      if (index == field_index.status)   fields.status    = cp;
      if (index == field_index.referer)  fields.referer   = cp;
      if (index == field_index.size)     fields.size      = cp;
      if (index == field_index.agent)    fields.agent     = cp;
      if (index == field_index.username) fields.username  = cp;
      
      /* Continue with the next data field */
      while (*cp) cp++;
      cp++;
      index++;
   }
   
   /* Save URL */
   if (fields.url)
   {
      cp = fields.url;
      while (*cp) { if (*cp=='+') *cp=' '; cp++; }

      /* If no HTTP Method, force to "NONE" */
      if (fields.method && (fields.method[0]=='-'))
         fields.method="NONE";

      if (fields.query && (fields.query[0]!='-'))
           snprintf(log_rec.url, MAXURL, "\"%s %s?%s\"",
                    fields.method, fields.url, fields.query);
      else snprintf(log_rec.url, MAXURL, "\"%s %s\"",
                    fields.method, fields.url);
   }
   else return 0;

   /* Save hostname */
   if (fields.ip) strncpy(log_rec.hostname, fields.ip, MAXHOST - 1);
      
   /* Save response code */
   if (fields.status) log_rec.resp_code = atoi(fields.status);
   
   /* Save referer */
   if (fields.referer) strncpy(log_rec.refer, fields.referer, MAXREF - 1);
   
   /* Save transfer size */
   if (fields.size) log_rec.xfer_size = strtoul(fields.size, NULL, 10);
   
   /* Save user agent */
   if (fields.agent)
   {
      cp = fields.agent;
      while (*cp) { if (*cp=='+') *cp=' '; cp++; }
      strncpy(log_rec.agent, fields.agent, MAXAGENT - 1);
   }
   
   /* Save auth username */
   if (fields.username) strncpy(log_rec.ident, fields.username, MAXIDENT - 1);
   
   /* Parse date and time and save it */
   if (fields.date)
   {
      gm_time.tm_year = atoi(fields.date);
      if (gm_time.tm_year > 1900) gm_time.tm_year-=1900;
      while ((fields.date[0] != '\0') && (fields.date[0] != '-')) fields.date++;
      if (fields.date[0] == '\0') return 0;
      fields.date++;
      gm_time.tm_mon = atoi(fields.date) - 1;
      while ((fields.date[0] != '\0') && (fields.date[0] != '-')) fields.date++;
      if (fields.date[0] == '\0') return 0;
      fields.date++;
      gm_time.tm_mday = atoi(fields.date);
   }
   if (fields.time)
   {
      gm_time.tm_hour = atoi(fields.time);
      while ((fields.time[0] != '\0') && (fields.time[0] != ':')) fields.time++;
      if (fields.time[0] == '\0') return 0;
      fields.time++;
      gm_time.tm_min = atoi(fields.time);
      while ((fields.time[0] != '\0') && (fields.time[0] != ':')) fields.time++;
      if (fields.time[0] == '\0') return 0;
      fields.time++;
      gm_time.tm_sec = atoi(fields.time);
   }
   
   /* Convert GMT to localtime */
   gm_time.tm_isdst = -1;                              /* force dst check   */
   timestamp = mktime(&gm_time);                       /* get time in sec   */
#ifdef HAVE_ALTZONE
   timestamp-=(gm_time.tm_isdst)?altzone:timezone;     /* solaris & friends */
#else
   timestamp = mktime(&gm_time)+gm_time.tm_gmtoff;     /* glibc systems     */
#endif
   local_time = localtime(&timestamp);                 /* update tm struct  */
   strftime(log_rec.datetime, sizeof(log_rec.datetime),/* and format sting  */
     "[%d/%b/%Y:%H:%M:%S -0000]", local_time);         /* for log_rec field */
   return 1;
}
