/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "./utils.h"

gchar*
lasso_safe_prefix_string(const gchar *str, gsize length)
{
	GString *output;
	gchar *ret;
	gsize outputted = 0, i = 0;

	fprintf (stderr, "Coin %s\n", str);
	if (str == NULL) {
		return strdup("NULL");
	}
	output = g_string_sized_new(length);
	for (i = 0; i < length && str[i] && outputted < length; i++) {
		gchar c = 0;
		guint len;

		if ((guchar)str[i] < 128 && (guchar)str[i] > 31) {
			g_string_append_c(output, str[i]);
			outputted++;
			continue;
		}
		switch (str[i]) {
			case '\n':
				c = 'n';
				break;
			case '\t':
				c = 't';
				break;
			case '\r':
				c = 'r';
		}
		if (c) {
			if (outputted - length > 1) {
				g_string_append_c(output, '\\');
				g_string_append_c(output, c);
				outputted += 2;
				continue;
			}
		}
		if (c < 8) {
			len = 3;
		} else if (c < 64) {
			len = 4;
		} else {
			len = 5;
		}
		if (outputted - length >= len) {
			g_string_append_c(output, '\\');
			g_string_append_printf(output, "%o", (guint)str[i]);
		}
		break;
	}
	ret = output->str;
	g_string_free(output, FALSE);
	return ret;
}
