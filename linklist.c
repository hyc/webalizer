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

#include "webalizer.h"                         /* main header              */
#include "lang.h"
#include "linklist.h"

/* internal function prototypes */

NLISTPTR new_nlist(char *);                         /* new list node       */
void     del_nlist(NLISTPTR *);                     /* del list            */

GLISTPTR new_glist(char *, char *);                 /* new group list node */
void     del_glist(GLISTPTR *);                     /* del group list      */

int      isinstr(char *, char *);

/* Linkded list pointers */
GLISTPTR group_sites   = NULL;                /* "group" lists            */
GLISTPTR group_urls    = NULL;
GLISTPTR group_refs    = NULL;
GLISTPTR group_agents  = NULL;
GLISTPTR group_users   = NULL;
NLISTPTR hidden_sites  = NULL;                /* "hidden" lists           */
NLISTPTR hidden_urls   = NULL;
NLISTPTR hidden_refs   = NULL;
NLISTPTR hidden_agents = NULL;
NLISTPTR hidden_users  = NULL;
NLISTPTR ignored_sites = NULL;                /* "Ignored" lists          */
NLISTPTR ignored_urls  = NULL;
NLISTPTR ignored_refs  = NULL;
NLISTPTR ignored_agents= NULL;
NLISTPTR ignored_users = NULL;
NLISTPTR include_sites = NULL;                /* "Include" lists          */
NLISTPTR include_urls  = NULL;
NLISTPTR include_refs  = NULL;
NLISTPTR include_agents= NULL;
NLISTPTR include_users = NULL;
NLISTPTR index_alias   = NULL;                /* index. aliases           */
NLISTPTR html_pre      = NULL;                /* before anything else :)  */
NLISTPTR html_head     = NULL;                /* top HTML code            */
NLISTPTR html_body     = NULL;                /* body HTML code           */
NLISTPTR html_post     = NULL;                /* middle HTML code         */
NLISTPTR html_tail     = NULL;                /* tail HTML code           */
NLISTPTR html_end      = NULL;                /* after everything else    */
NLISTPTR page_type     = NULL;                /* page view types          */
NLISTPTR omit_page     = NULL;                /* pages not counted        */
NLISTPTR page_prefix   = NULL;                /* page view prefixes       */
GLISTPTR search_list   = NULL;                /* Search engine list       */

/*********************************************/
/* NEW_NLIST - create new linked list node   */ 
/*********************************************/

NLISTPTR new_nlist(char *str)
{
   NLISTPTR newptr;

   if (sizeof(newptr->string) < strlen(str))
   {
      if (verbose)
    fprintf(stderr,"[new_nlist] %s\n",msg_big_one);
   }
   if (( newptr = malloc(sizeof(struct nlist))) != NULL)
    {strncpy(newptr->string, str, sizeof(newptr->string));newptr->next=NULL;}
   return newptr;
}

/*********************************************/
/* ADD_NLIST - add item to FIFO linked list  */
/*********************************************/

int add_nlist(char *str, NLISTPTR *list)
{
   NLISTPTR newptr,cptr,pptr;

   if ( (newptr = new_nlist(str)) != NULL)
   {
      if (*list==NULL) *list=newptr;
      else
      {
         cptr=pptr=*list;
         while(cptr!=NULL) { pptr=cptr; cptr=cptr->next; };
         pptr->next = newptr;
      }
   } 
   return newptr==NULL;
}

/*********************************************/
/* DEL_NLIST - delete FIFO linked list       */
/*********************************************/

void del_nlist(NLISTPTR *list)
{
   NLISTPTR cptr,nptr;

   cptr=*list;
   while (cptr!=NULL)
   {
      nptr=cptr->next;
      free(cptr);
      cptr=nptr;
   }
}

/*********************************************/
/* NEW_GLIST - create new linked list node   */ 
/*********************************************/

GLISTPTR new_glist(char *str, char *name)
{
   GLISTPTR newptr;

   if (sizeof(newptr->string) < strlen(str) ||
       sizeof(newptr->name) < strlen(name))
   {
      if (verbose)
	fprintf(stderr,"[new_glist] %s\n",msg_big_one);
   }
   if (( newptr = malloc(sizeof(struct glist))) != NULL)
     {
       strncpy(newptr->string, str, sizeof(newptr->string));
       strncpy(newptr->name, name, sizeof(newptr->name));
       newptr->next=NULL;
     }
   return newptr;
}

/*********************************************/
/* ADD_GLIST - add item to FIFO linked list  */
/*********************************************/

int add_glist(char *str, GLISTPTR *list)
{
   GLISTPTR newptr,cptr,pptr;
   char temp_buf[MAXKVAL];
   char *name=temp_buf;
   char sep=0;

   /* make local copy of string */
   if (*str=='"' || *str=='\'') sep=*str++;             /* Quote character?  */
   strncpy(temp_buf,str,MAXKVAL-1);
   temp_buf[MAXKVAL-1]=0;

   if (!sep)                                            /* Space separated   */
      while (!isspace((unsigned char)*name) && *name!=0) name++;
   else
      while (*name!=sep && *name!=0) name++;            /* Quote separated   */

   if (*name==0) name=temp_buf;
   else
   {
      *name++=0;
      while (isspace((unsigned char)*name)&&*name!=0) name++;
      if (*name==0) name=temp_buf;
   }

   if ( (newptr = new_glist(temp_buf, name)) != NULL)
   {
      if (*list==NULL) *list=newptr;
      else
      {
         cptr=pptr=*list;
         while(cptr!=NULL) { pptr=cptr; cptr=cptr->next; };
         pptr->next = newptr;
      }
   } 
   return newptr==NULL;
}

/*********************************************/
/* DEL_GLIST - delete FIFO linked list       */
/*********************************************/

void del_glist(GLISTPTR *list)
{
   GLISTPTR cptr,nptr;

   cptr=*list;
   while (cptr!=NULL)
   {
      nptr=cptr->next;
      free(cptr);
      cptr=nptr;
   }
}

/*********************************************/
/* ISINLIST - Test if string is in list      */
/*********************************************/

char *isinlist(NLISTPTR list, char *str)
{
   NLISTPTR lptr;

   lptr=list;
   while (lptr!=NULL)
   {
      if (isinstr(str,lptr->string)) return lptr->string;
      lptr=lptr->next;
   }
   return NULL;
}

/*********************************************/
/* ISINGLIST - Test if string is in list     */
/*********************************************/

char *isinglist(GLISTPTR list, char *str)
{
   GLISTPTR lptr;

   lptr=list;
   while (lptr!=NULL)
   {
      if (isinstr(str,lptr->string)) return lptr->name;
      lptr=lptr->next;
   }
   return NULL;
}

/*********************************************/
/* ISINSTR - Scan for string in string       */
/*********************************************/

int isinstr(char *str, char *cp)
{
   char *cp1,*cp2;

   cp1=(cp+strlen(cp))-1;
   if (*cp=='*')
   {
      /* if leading wildcard, start from end */
      cp2=str+strlen(str)-1;
      while ( (cp1!=cp) && (cp2!=str))
      {
         if (*cp1=='*') return 1;
         if (*cp1--!=*cp2--) return 0;
      }
      if (cp1==cp) return 1;
      else return 0;
   }
   else
   {
      /* if no leading/trailing wildcard, just strstr */
      if (*cp1!='*') return(strstr(str,cp)!=NULL);
      /* otherwise do normal forward scan */
      cp1=cp; cp2=str;
      while (*cp2!='\0')
      {
         if (*cp1=='*') return 1;
         if (*cp1++!=*cp2++) return 0;
      }
      if (*cp1=='*') return 1;
         else return 0;
   }
}
