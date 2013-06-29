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

#ifndef _LOGGER_H_INCLUDED_
#define _LOGGER_H_INCLUDED_

#include <stdarg.h>
#include <syslog.h>

extern int log_to_stderr;

void log_message(int nLevel, char *szFmt, ...);

#endif // _LOGGER_H_INCLUDED_
