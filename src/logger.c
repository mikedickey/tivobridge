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

#include "common.h"
#include "logger.h"

int log_to_stderr = 0;

void log_message(int nLevel, char *szFmt, ...)
{
	va_list ap;
	char buf[2048];

	va_start(ap, szFmt);
	int rc = vsnprintf(buf, 2047, szFmt, ap);
	va_end(ap);
	buf[2047] = 0;

	if (log_to_stderr)
		fprintf(stderr, "%s: %s\n", PACKAGE, buf);

	openlog(PACKAGE, 0, LOG_USER);
	syslog(nLevel, "%s", buf);
	closelog();
}
