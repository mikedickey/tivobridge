/* TiVoBridge - TiVo/mDNS packet repeater daemon
   Copyright (C) 2006  Brian Smith

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/

#ifndef _COMMON_H_INCLUDED_
#define _COMMON_H_INCLUDED_

#include "../config.h"

#if STDC_HEADERS
# include <string.h>
#else
# if !HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr (), *strrchr ();
#endif

#if !HAVE_STRDUP
char* strdup(char *str);
#endif

#if HAVE_MEMORY_H
# include <memory.h>
#endif
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif
#if HAVE_STRING_H
# include <string.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <stdio.h>

#include "my_stdint.h"

#endif
