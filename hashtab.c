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

/* some need for uint* */
#ifdef HAVE_STDINT_H
#include <stdint.h>
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
#include "linklist.h"
#include "hashtab.h"

/* internal function prototypes */

HNODEPTR new_hnode(char *);                   /* new host node            */
UNODEPTR new_unode(char *);                   /* new url node             */
RNODEPTR new_rnode(char *);                   /* new referrer node        */
ANODEPTR new_anode(char *);                   /* new user agent node      */
SNODEPTR new_snode(char *);                   /* new search string..      */
INODEPTR new_inode(char *);                   /* new ident node           */
#ifdef USE_DNS
DNODEPTR new_dnode(char *);                   /* new DNS node             */
#endif  /* USE_DNS */

void     update_entry(char *);                /* update entry/exit        */
void     update_exit(char *);                 /* page totals              */

unsigned int hash(char *);                    /* hash function            */

/* local data */

HNODEPTR sm_htab[MAXHASH];                    /* hash tables              */
HNODEPTR sd_htab[MAXHASH];
UNODEPTR um_htab[MAXHASH];                    /* for hits, sites,         */
RNODEPTR rm_htab[MAXHASH];                    /* referrers and agents...  */
ANODEPTR am_htab[MAXHASH];
SNODEPTR sr_htab[MAXHASH];                    /* search string table      */
INODEPTR im_htab[MAXHASH];                    /* ident table (username)   */
#ifdef USE_DNS
DNODEPTR host_table[MAXHASH];                 /* DNS hash table           */
#endif  /* USE_DNS */

/*********************************************/
/* DEL_HTABS - clear out our hash tables     */
/*********************************************/

void del_htabs()
{
   del_hlist(sd_htab);                        /* Clear out our various    */
   del_ulist(um_htab);                        /* hash tables here by      */
   del_hlist(sm_htab);                        /* calling the appropriate  */
   del_rlist(rm_htab);                        /* del_* fuction for each   */
   del_alist(am_htab);
   del_slist(sr_htab);
   del_ilist(im_htab);
#ifdef USE_DNS
/* del_dlist(host_table);  */                    /* delete DNS hash table    */
#endif  /* USE_DNS */
}

/*********************************************/
/* NEW_HNODE - create host node              */
/*********************************************/

HNODEPTR new_hnode(char *str)
{
   HNODEPTR newptr;
   char     *sptr;

   if (strlen(str) >= MAXHOST)
   {
      if (verbose)
      {
         fprintf(stderr,"[new_hnode] %s (%d)",msg_big_one,strlen(str));
         if (debug_mode)
            fprintf(stderr,":\n--> %s",str);
         fprintf(stderr,"\n");
      }
      str[MAXHOST-1]=0;
   }

   if ( (sptr=malloc(strlen(str)+1))==NULL ) return (HNODEPTR)NULL;
   strcpy(sptr,str);

   if (( newptr = malloc(sizeof(struct hnode))) != NULL)
   {
      newptr->string    =sptr;
      newptr->visit     =0;
      newptr->tstamp    =0;
      newptr->lasturl   =blank_str;
   }
   else free(sptr);
   return newptr;
}

/*********************************************/
/* PUT_HNODE - insert/update host node       */
/*********************************************/

int put_hnode( char      *str,  /* Hostname  */
               int       type,  /* obj type  */
               u_int64_t count, /* hit count */
               u_int64_t file,  /* File flag */
               double    xfer,  /* xfer size */
               u_int64_t *ctr,  /* counter   */
               u_int64_t visit, /* visits    */
               u_int64_t tstamp,/* timestamp */
               char      *lasturl, /* lasturl */
               HNODEPTR  *htab)  /* ptr>next  */
{
   HNODEPTR cptr,nptr;
   unsigned int hval;

   /* check if hashed */
   hval=hash(str);
   if ( (cptr = htab[hval]) == NULL)
   {
      /* not hashed */
      if ( (nptr=new_hnode(str)) != NULL)
      {
         nptr->flag  = type;
         nptr->count = count;
         nptr->files = file;
         nptr->xfer  = xfer;
         nptr->next  = NULL;
         htab[hval] = nptr;
         if (type!=OBJ_GRP) (*ctr)++;

         if (visit)
         {
            nptr->visit=(visit-1);
            nptr->lasturl=find_url(lasturl);
            nptr->tstamp=tstamp;
            return 0;
         }
         else
         {
            if (ispage(log_rec.url))
            {
               if (htab==sm_htab) update_entry(log_rec.url);
               nptr->lasturl=find_url(log_rec.url);
               nptr->tstamp=tstamp;
               nptr->visit=1;
            }
         }
      }
   }
   else
   {
      while (cptr != NULL)
      {
         if (strcmp(cptr->string,str)==0)
         {
            if ((type==cptr->flag)||((type!=OBJ_GRP)&&(cptr->flag!=OBJ_GRP)))
            {
               /* found... bump counter */
               cptr->count+=count;
               cptr->files+=file;
               cptr->xfer +=xfer;

               if (ispage(log_rec.url))
               {
                  if ((tstamp-cptr->tstamp)>=visit_timeout)
                  {
                     cptr->visit++;
                     if (htab==sm_htab)
                     {
                        update_exit(cptr->lasturl);
                        update_entry(log_rec.url);
                     }
                  }
                  cptr->lasturl=find_url(log_rec.url);
                  cptr->tstamp=tstamp;
               }
               return 0;
            }
         }
         cptr = cptr->next;
      }
      /* not found... */
      if ( (nptr = new_hnode(str)) != NULL)
      {
         nptr->flag  = type;
         nptr->count = count;
         nptr->files = file;
         nptr->xfer  = xfer;
         nptr->next  = htab[hval];
         htab[hval]=nptr;
         if (type!=OBJ_GRP) (*ctr)++;

         if (visit)
         {
            nptr->visit = (visit-1);
            nptr->lasturl=find_url(lasturl);
            nptr->tstamp= tstamp;
            return 0;
         }
         else
         {
            if (ispage(log_rec.url))
            {
               if (htab==sm_htab) update_entry(log_rec.url);
               nptr->lasturl=find_url(log_rec.url);
               nptr->tstamp= tstamp;
               nptr->visit=1;
            }
         }
      }
   }

   if (nptr!=NULL)
   {
      /* set object type */
      if (type==OBJ_GRP) nptr->flag=OBJ_GRP;            /* is it a grouping? */
      else
      {
         /* check if it's a hidden object */
         if ((hide_sites)||(isinlist(hidden_sites,nptr->string)!=NULL))
           nptr->flag=OBJ_HIDE;
      }
   }
   return nptr==NULL;
}

/*********************************************/
/* DEL_HLIST - delete host hash table        */
/*********************************************/

void	del_hlist(HNODEPTR *htab)
{
   /* free memory used by hash table */
   HNODEPTR aptr,temp;
   int i;

   for (i=0;i<MAXHASH;i++)
   {
      if (htab[i] != NULL)
      {
         aptr = htab[i];
         while (aptr != NULL)
         {
            temp = aptr->next;
            free (aptr->string);    /* free hostname string space */
            free (aptr);            /* free hostname structure    */
            aptr = temp;
         }
         htab[i]=NULL;
      }
   }
}

/*********************************************/
/* NEW_UNODE - URL node creation             */
/*********************************************/

UNODEPTR new_unode(char *str)
{
   UNODEPTR newptr;
   char     *sptr;

   if (strlen(str) >= MAXURLH)
   {
      if (verbose)
      {
         fprintf(stderr,"[new_unode] %s (%d)",msg_big_one,strlen(str));
         if (debug_mode)
            fprintf(stderr,":\n--> %s",str);
         fprintf(stderr,"\n");
      }
      str[MAXURLH-1]=0;
   }

   if ( (sptr=malloc(strlen(str)+1))==NULL) return (UNODEPTR)NULL;
   strcpy(sptr,str);

   if (( newptr = malloc(sizeof(struct unode))) != NULL)
   {
      newptr->string=sptr;
      newptr->count = 0;
      newptr->flag  = OBJ_REG;
   }
   else free(sptr);
   return newptr;
}

/*********************************************/
/* PUT_UNODE - insert/update URL node        */
/*********************************************/

int put_unode(char *str, int type, u_int64_t count, double xfer,
              u_int64_t *ctr, u_int64_t entry, u_int64_t exit, UNODEPTR *htab)
{
   UNODEPTR cptr,nptr;
   unsigned int hval;

   if (str[0]=='-') return 0;

   hval = hash(str);
   /* check if hashed */
   if ( (cptr = htab[hval]) == NULL)
   {
      /* not hashed */
      if ( (nptr=new_unode(str)) != NULL)
      {
         nptr->flag = type;
         nptr->count= count;
         nptr->xfer = xfer;
         nptr->next = NULL;
         nptr->entry= entry;
         nptr->exit = exit;
         htab[hval] = nptr;
         if (type!=OBJ_GRP) (*ctr)++;
      }
   }
   else
   {
      /* hashed */
      while (cptr != NULL)
      {
         if (strcmp(cptr->string,str)==0)
         {
            if ((type==cptr->flag)||((type!=OBJ_GRP)&&(cptr->flag!=OBJ_GRP)))
            {
               /* found... bump counter */
               cptr->count+=count;
               cptr->xfer += xfer;
               return 0;
            }
         }
         cptr = cptr->next;
      }
      /* not found... */
      if ( (nptr = new_unode(str)) != NULL)
      {
         nptr->flag = type;
         nptr->count= count;
         nptr->xfer = xfer;
         nptr->next = htab[hval];
         nptr->entry= entry;
         nptr->exit = exit;
         htab[hval] = nptr;
         if (type!=OBJ_GRP) (*ctr)++;
      }
   }
   if (nptr!=NULL)
   {
      if (type==OBJ_GRP) nptr->flag=OBJ_GRP;
      else if (isinlist(hidden_urls,nptr->string)!=NULL)
                         nptr->flag=OBJ_HIDE;
   }
   return nptr==NULL;
}

/*********************************************/
/* DEL_ULIST - delete URL hash table         */
/*********************************************/

void	del_ulist(UNODEPTR *htab)
{
   /* free memory used by hash table */
   UNODEPTR aptr,temp;
   int i;

   for (i=0;i<MAXHASH;i++)
   {
      if (htab[i] != NULL)
      {
         aptr = htab[i];
         while (aptr != NULL)
         {
            temp = aptr->next;
            free (aptr->string);  /* free up URL string memory */
            free (aptr);          /* free up URL struct node   */
            aptr = temp;
         }
         htab[i]=NULL;
      }
   }
}

/*********************************************/
/* NEW_RNODE - Referrer node creation        */
/*********************************************/

RNODEPTR new_rnode(char *str)
{
   RNODEPTR newptr;
   char     *sptr;

   if (strlen(str) >= MAXREFH)
   {
      if (verbose)
      {
         fprintf(stderr,"[new_rnode] %s (%d)",msg_big_one,strlen(str));
         if (debug_mode)
            fprintf(stderr,":\n--> %s",str);
         fprintf(stderr,"\n");
      }
      str[MAXREFH-1]=0;
   }

   if ( (sptr=malloc(strlen(str)+1))==NULL ) return (RNODEPTR)NULL;
   strcpy(sptr,str);

   if (( newptr = malloc(sizeof(struct rnode))) != NULL)
   {
      newptr->string= sptr;
      newptr->count = 1;
      newptr->flag  = OBJ_REG;
   }
   else free(sptr);
   return newptr;
}

/*********************************************/
/* PUT_RNODE - insert/update referrer node   */
/*********************************************/

int put_rnode(char *str, int type, u_int64_t count,
              u_int64_t *ctr, RNODEPTR *htab)
{
   RNODEPTR cptr,nptr;
   unsigned int hval;

   if (str[0]=='-') strcpy(str,"- (Direct Request)");

   hval = hash(str);
   /* check if hashed */
   if ( (cptr = htab[hval]) == NULL)
   {
      /* not hashed */
      if ( (nptr=new_rnode(str)) != NULL)
      {
         nptr->flag  = type;
         nptr->count = count;
         nptr->next  = NULL;
         htab[hval]  = nptr;
         if (type!=OBJ_GRP) (*ctr)++;
      }
   }
   else
   {
      while (cptr != NULL)
      {
         if (strcmp(cptr->string,str)==0)
         {
            if ((type==cptr->flag)||((type!=OBJ_GRP)&&(cptr->flag!=OBJ_GRP)))
            {
               /* found... bump counter */
               cptr->count+=count;
               return 0;
            }
         }
         cptr = cptr->next;
      }
      /* not found... */
      if ( (nptr = new_rnode(str)) != NULL)
      {
         nptr->flag  = type;
         nptr->count = count;
         nptr->next  = htab[hval];
         htab[hval]  = nptr;
         if (type!=OBJ_GRP) (*ctr)++;
      }
   }
   if (nptr!=NULL)
   {
      if (type==OBJ_GRP) nptr->flag=OBJ_GRP;
      else if (isinlist(hidden_refs,nptr->string)!=NULL)
                         nptr->flag=OBJ_HIDE;
   }
   return nptr==NULL;
}

/*********************************************/
/* DEL_RLIST - delete referrer hash table    */
/*********************************************/

void	del_rlist(RNODEPTR *htab)
{
   /* free memory used by hash table */
   RNODEPTR aptr,temp;
   int i;

   for (i=0;i<MAXHASH;i++)
   {
      if (htab[i] != NULL)
      {
         aptr = htab[i];
         while (aptr != NULL)
         {
            temp = aptr->next;
            free (aptr->string);
            free (aptr);
            aptr = temp;
         }
         htab[i]=NULL;
      }
   }
}

/*********************************************/
/* NEW_ANODE - User Agent node creation      */
/*********************************************/

ANODEPTR new_anode(char *str)
{
   ANODEPTR newptr;
   char     *sptr;

   if (strlen(str) >= MAXAGENT)
   {
      if (verbose)
      {
         fprintf(stderr,"[new_anode] %s (%d)",msg_big_one,strlen(str));
         if (debug_mode)
            fprintf(stderr,":\n--> %s",str);
         fprintf(stderr,"\n");
      }
      str[MAXAGENT-1]=0;
   }

   if ( (sptr=malloc(strlen(str)+1))==NULL ) return (ANODEPTR)NULL;
   strcpy(sptr,str);

   if (( newptr = malloc(sizeof(struct anode))) != NULL)
   {
      newptr->string= sptr;
      newptr->count = 1;
      newptr->flag  = OBJ_REG;
   }
   else free(sptr);
   return newptr;
}

/*********************************************/
/* PUT_ANODE - insert/update user agent node */
/*********************************************/

int put_anode(char *str, int type, u_int64_t count,
              u_int64_t *ctr, ANODEPTR *htab)
{
   ANODEPTR cptr,nptr;
   unsigned int hval;

   if (str[0]=='-') return 0;     /* skip bad user agents */

   hval = hash(str);
   /* check if hashed */
   if ( (cptr = htab[hval]) == NULL)
   {
      /* not hashed */
      if ( (nptr=new_anode(str)) != NULL)
      {
         nptr->flag = type;
         nptr->count= count;
         nptr->next = NULL;
         htab[hval] = nptr;
         if (type!=OBJ_GRP) (*ctr)++;
      }
   }
   else
   {
      /* hashed */
      while (cptr != NULL)
      {
         if (strcmp(cptr->string,str)==0)
         {
            if ((type==cptr->flag)||((type!=OBJ_GRP)&&(cptr->flag!=OBJ_GRP)))
            {
               /* found... bump counter */
               cptr->count+=count;
               return 0;
            }
         }
         cptr = cptr->next;
      }
      /* not found... */
      if ( (nptr = new_anode(str)) != NULL)
      {
         nptr->flag  = type;
         nptr->count = count;
         nptr->next  = htab[hval];
         htab[hval]  = nptr;
         if (type!=OBJ_GRP) (*ctr)++;
      }
   }
   if (type==OBJ_GRP) nptr->flag=OBJ_GRP;
   else if (isinlist(hidden_agents,nptr->string)!=NULL)
                      nptr->flag=OBJ_HIDE;
   return nptr==NULL;
}

/*********************************************/
/* DEL_ALIST - delete user agent hash table  */
/*********************************************/

void	del_alist(ANODEPTR *htab)
{
   /* free memory used by hash table */
   ANODEPTR aptr,temp;
   int i;

   for (i=0;i<MAXHASH;i++)
   {
      if (htab[i] != NULL)
      {
         aptr = htab[i];
         while (aptr != NULL)
         {
            temp = aptr->next;
            free (aptr->string);
            free (aptr);
            aptr = temp;
         }
         htab[i]=NULL;
      }
   }
}

/*********************************************/
/* NEW_SNODE - Search str node creation      */
/*********************************************/

SNODEPTR new_snode(char *str)
{
   SNODEPTR newptr;
   char     *sptr;

   if (strlen(str) >= MAXSRCHH)
   {
      if (verbose)
      {
         fprintf(stderr,"[new_snode] %s (%d)",msg_big_one,strlen(str));
         if (debug_mode)
            fprintf(stderr,":\n--> %s",str);
         fprintf(stderr,"\n");
      }
      str[MAXSRCHH-1]=0;
   }

   if ( (sptr=malloc(strlen(str)+1))==NULL ) return (SNODEPTR)NULL;
   strcpy(sptr,str);

   if (( newptr = malloc(sizeof(struct snode))) != NULL)
   {
      newptr->string= sptr;
      newptr->count = 1;
   }
   else free(sptr);
   return newptr;
}

/*********************************************/
/* PUT_SNODE - insert/update search str node */
/*********************************************/

int put_snode(char *str, u_int64_t count, SNODEPTR *htab)
{
   SNODEPTR cptr,nptr;
   unsigned int hval;

   if (str[0]==0 || str[0]==' ') return 0;     /* skip bad search strs */

   hval=hash(str);
   /* check if hashed */
   if ( (cptr = htab[hval]) == NULL)
   {
      /* not hashed */
      if ( (nptr=new_snode(str)) != NULL)
      {
         nptr->count = count;
         nptr->next = NULL;
         htab[hval] = nptr;
      }
   }
   else
   {
      /* hashed */
      while (cptr != NULL)
      {
         if (strcmp(cptr->string,str)==0)
         {
            /* found... bump counter */
            cptr->count+=count;
            return 0;
         }
         cptr = cptr->next;
      }
      /* not found... */
      if ( (nptr = new_snode(str)) != NULL)
      {
         nptr->count = count;
         nptr->next  = htab[hval];
         htab[hval]  = nptr;
      }
   }
   return nptr==NULL;
}

/*********************************************/
/* DEL_SLIST - delete search str hash table  */
/*********************************************/

void	del_slist(SNODEPTR *htab)
{
   /* free memory used by hash table */
   SNODEPTR aptr,temp;
   int i;

   for (i=0;i<MAXHASH;i++)
   {
      if (htab[i] != NULL)
      {
         aptr = htab[i];
         while (aptr != NULL)
         {
            temp = aptr->next;
            free (aptr->string);
            free (aptr);
            aptr = temp;
         }
         htab[i]=NULL;
      }
   }
}

/*********************************************/
/* NEW_INODE - create ident (username) node  */
/*********************************************/

INODEPTR new_inode(char *str)
{
   INODEPTR newptr;
   char     *sptr;

   if (strlen(str) >= MAXIDENT)
   {
      if (verbose)
      {
         fprintf(stderr,"[new_inode] %s (%d)",msg_big_one,strlen(str));
         if (debug_mode)
            fprintf(stderr,":\n--> %s",str);
         fprintf(stderr,"\n");
      }
      str[MAXIDENT-1]=0;
   }

   if ( (sptr=malloc(strlen(str)+1))==NULL ) return (INODEPTR)NULL;
   strcpy(sptr,str);

   if (( newptr = malloc(sizeof(struct inode))) != NULL)
   {
      newptr->string    =sptr;
      newptr->visit     =1;
      newptr->tstamp    =0;
   }
   else free(sptr);
   return newptr;
}

/*********************************************/
/* PUT_INODE - insert/update ident node      */
/*********************************************/

int put_inode( char      *str,  /* ident str */
               int       type,  /* obj type  */
               u_int64_t count, /* hit count */
               u_int64_t file,  /* File flag */
               double    xfer,  /* xfer size */
               u_int64_t *ctr,  /* counter   */
               u_int64_t visit, /* visits    */
               u_int64_t tstamp,/* timestamp */
               INODEPTR  *htab) /* hashtable */
{
   INODEPTR cptr,nptr;
   unsigned int hval;

   if ((str[0]=='-') || (str[0]==0)) return 0;  /* skip if no username */

   hval = hash(str);
   /* check if hashed */
   if ( (cptr = htab[hval]) == NULL)
   {
      /* not hashed */
      if ( (nptr=new_inode(str)) != NULL)
      {
         nptr->flag  = type;
         nptr->count = count;
         nptr->files = file;
         nptr->xfer  = xfer;
         nptr->next  = NULL;
         htab[hval] = nptr;
         if (type!=OBJ_GRP) (*ctr)++;

         if (visit)
         {
            nptr->visit=(visit-1);
            nptr->tstamp=tstamp;
            return 0;
         }
         else
         {
            if (ispage(log_rec.url)) nptr->tstamp=tstamp;
         }
      }
   }
   else
   {
      /* hashed */
      while (cptr != NULL)
      {
         if (strcmp(cptr->string,str)==0)
         {
            if ((type==cptr->flag)||((type!=OBJ_GRP)&&(cptr->flag!=OBJ_GRP)))
            {
               /* found... bump counter */
               cptr->count+=count;
               cptr->files+=file;
               cptr->xfer +=xfer;

               if (ispage(log_rec.url))
               {
                  if ((tstamp-cptr->tstamp)>=visit_timeout)
                     cptr->visit++;
                  cptr->tstamp=tstamp;
               }
               return 0;
            }
         }
         cptr = cptr->next;
      }
      /* not found... */
      if ( (nptr = new_inode(str)) != NULL)
      {
         nptr->flag  = type;
         nptr->count = count;
         nptr->files = file;
         nptr->xfer  = xfer;
         nptr->next  = htab[hval];
         htab[hval]  = nptr;
         if (type!=OBJ_GRP) (*ctr)++;

         if (visit)
         {
            nptr->visit = (visit-1);
            nptr->tstamp= tstamp;
            return 0;
         }
         else
         {
            if (ispage(log_rec.url)) nptr->tstamp= tstamp;
         }
      }
   }

   if (nptr!=NULL)
   {
      /* set object type */
      if (type==OBJ_GRP) nptr->flag=OBJ_GRP;            /* is it a grouping? */
      else
      {
         /* check if it's a hidden object */
         if (isinlist(hidden_users,nptr->string)!=NULL)
           nptr->flag=OBJ_HIDE;
      }
   }
   return nptr==NULL;
}

/*********************************************/
/* DEL_ILIST - delete ident hash table       */
/*********************************************/

void	del_ilist(INODEPTR *htab)
{
   /* free memory used by hash table */
   INODEPTR aptr,temp;
   int i;

   for (i=0;i<MAXHASH;i++)
   {
      if (htab[i] != NULL)
      {
         aptr = htab[i];
         while (aptr != NULL)
         {
            temp = aptr->next;
            free (aptr->string);    /* free ident string space */
            free (aptr);            /* free ident structure    */
            aptr = temp;
         }
         htab[i]=NULL;
      }
   }
}

#ifdef USE_DNS   /* only add these for DNS   */

/*********************************************/
/* NEW_DNODE - DNS resolver node creation    */
/*********************************************/

DNODEPTR new_dnode(char *str)
{
   DNODEPTR newptr;
   char     *sptr;

   if (strlen(str) >= MAXHOST)
   {
      if (verbose)
      {
         fprintf(stderr,"[new_dnode] %s (%d)",msg_big_one,strlen(str));
         if (debug_mode)
            fprintf(stderr,":\n--> %s",str);
         fprintf(stderr,"\n");
      }
      str[MAXHOST-1]=0;
   }

   if ( (sptr=malloc(strlen(str)+1))==NULL ) return (DNODEPTR)NULL;
   strcpy(sptr,str);

   if (( newptr = malloc(sizeof(struct dnode))) != NULL)
   {
      newptr->string= sptr;
   }
   else free(sptr);
   return newptr;
}

/*********************************************/
/* PUT_DNODE - insert/update dns host node   */
/*********************************************/

int put_dnode(char *str, void *addr, int len, DNODEPTR *htab)
{
   DNODEPTR cptr,nptr;
   unsigned int hval;

   if (str[0]==0 || str[0]==' ') return 0;     /* skip bad hostnames */

   hval = hash(str);
   /* check if hashed */
   if ( (cptr = htab[hval]) == NULL)
   {
      /* not hashed */
      if ( (nptr=new_dnode(str)) != NULL)
      {
         if (addr) memcpy(&nptr->addr, addr, len);
            else   memset(&nptr->addr, 0, sizeof(struct sockaddr_storage));
         nptr->addrlen = len;
         nptr->next = NULL;
         htab[hval] = nptr;
      }
   }
   else
   {
      /* hashed */
      while (cptr != NULL)
      {
         if (strcmp(cptr->string,str)==0) return 0;
         cptr = cptr->next;
      }
      /* not found... */
      if ( (nptr = new_dnode(str)) != NULL)
      {
         if (addr) memcpy(&nptr->addr, addr, len);
            else   memset(&nptr->addr, 0, sizeof(struct sockaddr_storage));
         nptr->addrlen = len;
         nptr->next  = htab[hval];
         htab[hval]  = nptr;
      }
   }
   return nptr==NULL;
}

/*********************************************/
/* DEL_DLIST - delete dns hash table         */
/*********************************************/

void	del_dlist(DNODEPTR *htab)
{
   /* free memory used by hash table */
   DNODEPTR dptr,temp;
   int i;

   for (i=0;i<MAXHASH;i++)
   {
      if (htab[i] != NULL)
      {
         dptr = htab[i];
         while (dptr != NULL)
         {
            temp = dptr->next;
            free (dptr->string);
            free (dptr);
            dptr = temp;
         }
         htab[i]=NULL;
      }
   }
}

#endif /* USE_DNS */

/*********************************************/
/* FIND_URL - Find URL in hash table         */
/*********************************************/

char *find_url(char *str)
{
   UNODEPTR cptr;

   if ( (cptr=um_htab[hash(str)]) != NULL)
   {
      while (cptr != NULL)
      {
         if (strcmp(cptr->string,str)==0)
            return cptr->string;
         cptr = cptr->next;
      }
   }
   return blank_str;   /* shouldn't get here */
}

/*********************************************/
/* UPDATE_ENTRY - update entry page total    */
/*********************************************/

void update_entry(char *str)
{
   UNODEPTR uptr;

   if (str==NULL) return;
   if ( (uptr = um_htab[hash(str)]) == NULL) return;
   else
   {
      while (uptr != NULL)
      {
         if (strcmp(uptr->string,str)==0)
         {
            if (uptr->flag!=OBJ_GRP)
            {
               uptr->entry++;
               return;
            }
         }
         uptr=uptr->next;
      }
   }
}

/*********************************************/
/* UPDATE_EXIT  - update exit page total     */
/*********************************************/

void update_exit(char *str)
{
   UNODEPTR uptr;

   if (str==NULL) return;
   if ( (uptr = um_htab[hash(str)]) == NULL) return;
   else
   {
      while (uptr != NULL)
      {
         if (strcmp(uptr->string,str)==0)
         {
            if (uptr->flag!=OBJ_GRP)
            {
               uptr->exit++;
               return;
            }
         }
         uptr=uptr->next;
      }
   }
}

/*********************************************/
/* MONTH_UPDATE_EXIT  - eom exit page update */
/*********************************************/

void month_update_exit(u_int64_t tstamp)
{
   HNODEPTR nptr;
   int i;

   for (i=0;i<MAXHASH;i++)
   {
      nptr=sm_htab[i];
      while (nptr!=NULL)
      {
         if (nptr->flag!=OBJ_GRP)
         {
            if ((tstamp-nptr->tstamp)>=visit_timeout)
               update_exit(nptr->lasturl);
         }
         nptr=nptr->next;
      }
   }
}

/*********************************************/
/* TOT_VISIT - calculate total visits        */
/*********************************************/

u_int64_t tot_visit(HNODEPTR *list)
{
   HNODEPTR   hptr;
   u_int64_t  tot=0;
   int        i;

   for (i=0;i<MAXHASH;i++)
   {
      hptr=list[i];
      while (hptr!=NULL)
      {
         if (hptr->flag!=OBJ_GRP) tot+=hptr->visit;
         hptr=hptr->next;
      }
   }
   return tot;
}

#ifdef USE_OLDHASH
/*********************************************/
/* HASH - return hash value for string       */
/*********************************************/

unsigned int hash(char *str)
{
   uint32_t  hashval=0;

   for (hashval = 0; *str != '\0'; str++)
      hashval = *str + (hashval << 5) - hashval;

   return hashval % MAXHASH;
}

#else /* USE_OLDHASH */
/*********************************************/
/* HASH (SuperFastHash by Paul Hsieh)        */
/*********************************************/

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

unsigned int hash(char *str)
{
   int len=strlen(str);
   uint32_t hash = len, tmp;
   int rem;

   if (len <= 0 || str == NULL) return 0;

   rem = len & 3;
   len >>= 2;

   /* Main loop */
   for (;len > 0; len--)
   {
      hash  += get16bits (str);
      tmp    = (get16bits (str+2) << 11) ^ hash;
      hash   = (hash << 16) ^ tmp;
      str   += 2*sizeof (uint16_t);
      hash  += hash >> 11;
   }

   /* Handle end cases */
   switch (rem)
   {
      case 3: hash += get16bits (str);
              hash ^= hash << 16;
              hash ^= str[sizeof (uint16_t)] << 18;
              hash += hash >> 11;
              break;
      case 2: hash += get16bits (str);
              hash ^= hash << 11;
              hash += hash >> 17;
              break;
      case 1: hash += *str;
              hash ^= hash << 10;
              hash += hash >> 1;
   }

   /* Force "avalanching" of final 127 bits */
   hash ^= hash << 3;
   hash += hash >> 5;
   hash ^= hash << 4;
   hash += hash >> 17;
   hash ^= hash << 25;
   hash += hash >> 6;

   return hash % MAXHASH;
}
#endif /* USE_OLDHASH */
