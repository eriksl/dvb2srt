/* 
 
   (C) Erik Slagter 2009

   very loosely based on:

		dvbtextsubs - a teletext subtitles decoder for DVB cards. 
		(C) Dave Chapman <dave@dchapman.com> 2003-2004.

		Thanks to:  

		Ralph Metzler (re: dvbtext - dvbtextsubs is based heavily on dvbtext)
		for his work on both the DVB driver and his old vbidecode package
		(some code and ideas in dvbtext are borrowed from vbidecode).

		Jan Panteltje for his advice and his work on submux-dvd

		Ragnar Sundblad (the author of the VDR teletext subtitles plugin) for
		his help in adding VDR support to dvbtextsubs and for suggesting
		various improvements.

		Scott T. Smith for creating "dvdauthor".

	Copyright notice:

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
	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <ncurses.h>
#include <stdarg.h>

#include "tables.h"
#include "vtxdecode.h"

typedef int64_t pts_t;

#if defined(bool)
#undef bool
#endif

#if defined(false)
#undef false
#endif

#if defined(true)
#undef true
#endif

typedef enum
{
	false = 0,
	true = 1
} bool;

typedef enum
{
	ttx_page_row_size = 24,
	ttx_page_col_size = 40
} ttx_page_size;

typedef struct
{
	int		pid;
	bool	ignore;
	bool	target;
	int		counter;
	int		local_continuity_counter;
	int		remote_continuity_counter;
	bool	skip_to_pes_payload_start;
	int		pes_payload_start;
	int		pes_payload_length;
	int		pes_stream_id;
	int		pes_sub_id;
	pts_t	pts;

	int		stat_invalid_pes_header;
	int		stat_lost;
	int		stat_nopayload;
	int		stat_invalid_header;
	int		stat_discard;
	int		stat_skipped;
	int		stat_payload_oversize;

	unsigned char * payload_buffer;
	size_t			payload_offset;
	size_t			payload_alloc;
} ts_pid_t;

typedef struct
{
	pts_t			from_pts, from_pts_z;
	pts_t			to_pts, to_pts_z;
	const char *	text;
} subtitle_t;

typedef unsigned char ttx_page_t[ttx_page_row_size][ttx_page_col_size];

static pts_t option_offset	= 0;

static bool	flag_debug		= false;
static bool	flag_hexdump	= false;
static bool	flag_view		= false;
static bool flag_ssa		= true;
static bool flag_compress	= false;

__attribute__ ((used)) static void error(const char * format, ...)
{
	va_list	ap;
	char	buffer[256];

	strcpy(buffer, "ERROR: ");
	
	va_start(ap, format);
	vsnprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), format, ap);

	if(flag_view)
	{
		mvaddstr(24, 0, buffer);
		refresh();
		sleep(1);
	}
	else
		fprintf(stderr, buffer);
}


static void warning(const char * format, ...)
{
	va_list	ap;
	char	buffer[256];

	strcpy(buffer, "WARNING: ");
	
	va_start(ap, format);
	vsnprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), format, ap);

	if(flag_view)
	{
		mvaddstr(24, 0, buffer);
		refresh();
		// sleep(1);
	}
	else
		fprintf(stderr, buffer);
}

static void debug(const char * format, ...)
{
	va_list	ap;
	char	buffer[256];

	if(!flag_debug)
		return;

	strcpy(buffer, "DEBUG: ");
	
	va_start(ap, format);
	vsnprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), format, ap);

	if(flag_view)
	{
		mvaddstr(24, 0, buffer);
		refresh();
		//sleep(1);
	}
	else
		fprintf(stderr, buffer);
}

static void hexdump(const unsigned char * buffer, size_t length, ssize_t payload_indicator)
{
	int y, x, o, b, a;
	char outbuffer[32];

	if(flag_view)
		move(0, 0);

	for(y = 0; y < ((length / 10) + 1); y++)
	{
		snprintf(outbuffer, sizeof(outbuffer), "%2d  ", y);

		if(flag_view)
			addstr(outbuffer);
		else
			fprintf(stderr, outbuffer);
	
		for(x = 0; x < 10; x++)
		{
			o = y * 10 + x;
	
			if(o < length)
			{
				b = buffer[o];
				a = (b >= ' ' && b <= '~') ? b : ' ';
				snprintf(outbuffer, sizeof(outbuffer), "%s%2x %c    ", o == payload_indicator ? "*" : " ", b, a);

				if(flag_view)
					addstr(outbuffer);
				else
					fprintf(stderr, outbuffer);
			}
		}

		if(flag_view)
			refresh();
		else
			fprintf(stderr, "\n");
	}
}

__attribute__((used)) static const char * asciidump(const unsigned char * buffer, size_t length)
{
	int						x;
	const unsigned char *	in;
	unsigned char *			out;
	static unsigned char	rv[256];

	for(x = 0, in = buffer, out = rv; (x < length) && (x < (sizeof(rv) - 2)); x++, in++, out++)
		if(isprint(*in))
			*out = *in;
		else
			*out = '#';

	*out++ = '\0';

	return((const char *)rv);
}

__attribute__ ((used)) static int page2ttx(int page_in)
{
	int retval1, retval2;
	int nibble[3];
	int page;

	retval1 = (page_in % 10) | ((((page_in - (100 * (page_in / 100))) % 100) / 10) <<4 ) | ((page_in / 100) << 8);

	nibble[2]	=	page_in / 100;
	page		=	page_in - nibble[2] * 100;
	nibble[1]	=	page / 10;
	page		-=	nibble[1] * 10;
	nibble[0]	=	page;

	retval2 = (nibble[2] << 8) | (nibble[1] << 4) | (nibble[0] << 0);

	return(retval2);
}

__attribute__((used)) static const char * ttx2pagestr(int ttx)
{
	static char retval[8];

	snprintf(retval, sizeof(retval), "%x", ttx);

	return(retval);
}

static int ttx2page(int ttx)
{
	int retval = 0;
	int ix;

	for(ix = 0; ix < 4; ix++)
	{
		retval *= 10;
		retval += (ttx & 0xf000) >> 12;
		ttx <<= 4;
	}

	return(retval);
}

static pts_t pes2pts(const unsigned char * buffer)
{
	int		byte[5];
	int		ix;
	pts_t	pts;

	byte[0] = (buffer[4] & 0xfe) >> 1 | ((buffer[3] & 1) << 7);
	byte[1] = (buffer[3] & 0xfe) >> 1 | ((buffer[2] & 2) << 6);
	byte[2] = (buffer[2] & 0xfc) >> 2 | ((buffer[1] & 3) << 6);
	byte[3] = (buffer[1] & 0xfc) >> 2 | ((buffer[0] & 6) << 5);
	byte[4] = (buffer[0] & 0x08) >> 3;

	for(ix = 0; ix < 5; ix++)
	{
		pts <<= 8;
		pts |= byte[4 - ix];
	}

	return(pts);
}

static const char * pts2str(bool ssa, pts_t pts)
{
	static char	rv[16];
	int			hours;
	int			minutes;
	int			seconds;
	int			msecs;
	int			csecs;
	int			integer;
	int			fraction;

	if(pts >= 0)
	{
		fraction	=	pts % 90000;
		msecs		=	fraction / 90;
		csecs		=	fraction / 900;
		integer		=	pts / 90000;
		hours		=	integer / 3600;
		integer		-=	hours * 3600;
		minutes		=	integer / 60;
		integer		-=	minutes * 60;
		seconds		=	integer;
	}
	else
		hours = minutes = seconds = csecs = msecs = -1;

	if(ssa)
		snprintf(rv, sizeof(rv), "%d:%1.1d:%2.2d.%2.2d", 
				hours, minutes, seconds, csecs);
	else
		snprintf(rv, sizeof(rv), "%2.2d:%2.2d:%2.2d,%3.3d", 
				hours, minutes, seconds, msecs);

	return(rv);
}

static void bit_reverse(unsigned char * buffer, size_t length)
{
	int ix;

	for(ix = 0; ix < length; ix++)
		buffer[ix] = invtab[buffer[ix]];
}

static void remove_parity(unsigned char * buffer, size_t length)
{
	int ix;

	for(ix = 0; ix < length; ix++)
		buffer[ix] = buffer[ix] & 0x7f;
}

static void unham(const unsigned char * in, unsigned char * out, int hambytes)
{
	int						ix;
	const	unsigned char *	inp;
			unsigned char *	outp;

	for(ix = 0, inp = in, outp = out; ix < (hambytes / 2); ix++, outp++)
	{
		*outp	=	((unhamtab[*(inp++)] & 0x0f) << 0);
		*outp	|=	((unhamtab[*(inp++)] & 0x0f) << 4);
	}
}

static void push_sub(FILE * out_z, FILE * out_nz, subtitle_t * new_sub)
{
	static subtitle_t *	prev_sub	= 0;
	static int			subindex	= 0;

	if(prev_sub)
	{
		if(prev_sub->to_pts == -1)
		{
			prev_sub->to_pts	= new_sub->from_pts;
			prev_sub->to_pts_z	= new_sub->from_pts_z;
		}
	}

	if(!strlen(new_sub->text))
		return;

	if(flag_compress && prev_sub)
	{
		if(!strncmp(prev_sub->text, new_sub->text, strlen(prev_sub->text)))
		{
			free((void *)prev_sub->text);
			prev_sub->text		= new_sub->text;
			new_sub->text		= 0;
			prev_sub->to_pts	= -1;
			prev_sub->to_pts_z	= -1;

			return;
		}
	}

	if(prev_sub)
	{
		subindex++;

		if(flag_ssa)
		{
			fprintf(out_nz, "Dialogue: Marked=%d,", subindex);
			fprintf(out_nz, "%s,", pts2str(true, prev_sub->from_pts));
			fprintf(out_nz, "%s,", pts2str(true, prev_sub->to_pts));
			fprintf(out_nz, "default,name,0000,0000,0000,,");
			fprintf(out_nz, "%s\n", prev_sub->text);

			fprintf(out_z, "Dialogue: Marked=%d,", subindex);
			fprintf(out_z, "%s,", pts2str(true, prev_sub->from_pts_z));
			fprintf(out_z, "%s,", pts2str(true, prev_sub->to_pts_z));
			fprintf(out_z, "default,name,0000,0000,0000,,");
			fprintf(out_z, "%s\n", prev_sub->text);
		}
		else
		{
			fprintf(out_nz, "%d\n", subindex);
			fprintf(out_nz, "%s --> ", pts2str(false, prev_sub->from_pts));
			fprintf(out_nz, "%s\n", pts2str(false, prev_sub->to_pts));
			fprintf(out_nz, "%s\n\n", prev_sub->text);

			fprintf(out_z, "%d\n", subindex);
			fprintf(out_z, "%s --> ", pts2str(false, prev_sub->from_pts_z));
			fprintf(out_z, "%s\n", pts2str(false, prev_sub->to_pts_z));
			fprintf(out_z, "%s\n\n", prev_sub->text);
		}

		fflush(out_nz);
		fflush(out_z);

		free((void *)prev_sub->text);
		free(prev_sub);
	}

	prev_sub = new_sub;
}

static subtitle_t * make_sub(pts_t first_pts, pts_t pts, const char * text)
{
	pts_t			pts_z;
	subtitle_t *	sub;

	pts	+= option_offset;

	if((first_pts != -1))
	{
		if(pts > first_pts)
			pts_z = pts - first_pts;
		else
			pts_z = (pts + 0x1ffffffff) - first_pts;
	}
	else
		pts_z = pts;

	sub = malloc(sizeof(*sub));

	sub->text		= text;
	sub->from_pts	= pts;
	sub->from_pts_z	= pts_z;
	sub->to_pts		= -1;
	sub->to_pts_z	= -1;

	return(sub);
}

static const char * page_to_line(ttx_page_t page)
{
	char *				subtitle			= 0;
	int					subtitle_alloc		= 0;
	int					subtitle_offset		= 0;
	unsigned char *		current;
	int					subtitle_col		= 0;
	bool				row_attr_set		= false;
	bool				last_char_is_blank	= false;
	int					page_row;
	int					page_col;

	static const char * ttx_colours[] =
	{
		"666666",	//	black
		"0000ff",	//	red
		"00ff00",	//	green
		"00ffff",	//	yellow
		"ff6666",	//	blue
		"ff00ff",	//	magenta
		"ffff00",	//	cyan
		"ffffff",	//	white
	};

	for(page_row = 0; page_row < ttx_page_row_size; page_row++)
	{
		row_attr_set = false;

		for(page_col = 0; page_col < ttx_page_col_size; page_col++)
		{
			current = &page[page_row][page_col];

			/*
			 * reserve room for at least:
			 *	 1 bytes new character
			 *	12 bytes ssa colour
			 *	12 bytes ssa colour reset on new line
			 */

			if(subtitle_alloc < (subtitle_offset + 32))
			{
				subtitle_alloc += 256;
				subtitle = (char *)realloc(subtitle, subtitle_alloc);
			}

			if(*current < ' ')
			{
				if(flag_ssa && ((*current >= 0) && (*current < (sizeof(ttx_colours) / sizeof(*ttx_colours)))))
				{
					sprintf((char *)&subtitle[subtitle_offset], "{\\cH%6.6s&}", ttx_colours[*current]);
					subtitle_offset += 12;
					row_attr_set = true;
				}

				*current = ' ';
			}

			if(*current == ' ')
			{
				if((subtitle_col != 0) && (subtitle_offset != 0) && (!last_char_is_blank))
				{
					subtitle[subtitle_offset++] = ' ';
					subtitle_col++;
					last_char_is_blank = true;
				}
			}
			else
			{
				if(flag_ssa && !row_attr_set)
				{
					memcpy(&subtitle[subtitle_offset], "{\\cHFFFFFF&}", 12);
					subtitle_offset += 12;
					row_attr_set = true;
				}

				subtitle[subtitle_offset++] = *current;
				subtitle_col++;
				last_char_is_blank = false;
			}
		}
	}

	while((subtitle_offset > 0) && (subtitle[subtitle_offset - 1] == ' '))
		subtitle_offset--;

	subtitle[subtitle_offset] = 0;

	return(subtitle);
}

static void view_page(pts_t pts, int pagenum, int subpage, ttx_page_t page)
{
	char	buffer[128];
	int		current;
	int		line;
	int		column;

	move(0, 30);
	snprintf(buffer, sizeof(buffer), "%3.3d/%4.4d ", pagenum, subpage);
	addstr(buffer);
	snprintf(buffer, sizeof(buffer), "%s\n", pts2str(false, pts));	
	addstr(buffer);

	for(line = 0; line < ttx_page_row_size; line++)
	{
		for(column = 0; column < ttx_page_col_size; column++)
		{
			current = page[line][column];

			if((current < 32) || (current > 127))
				current = ' ';

			buffer[column] = current;
		}

		buffer[column] = 0;
		mvaddstr(line + 2, 0, buffer);
	}

	refresh();
}

/*
 * 0-2	start code		0x000001
 * 3	stream id
 * 4-5	pes packet length
 * 6	optional pes header flags 1
 * 		7-6	marker bits
 * 		5-4	scrambling control
 * 		3	priority
 * 		2	data alignment indicator
 * 		1	copyright
 * 		0	original/copy
 * 7	optional pes header flags 2
 * 		7	pts present
 * 		6	dts present
 * 		5	escr flag
 * 		4	es rate flag
 * 		3	dsm trick mode flag
 * 		2	additional copy info flag
 * 		1	crc flag
 * 		0	extension flag
 * 8	optional pes header length
 * 9	optional fields
 * x	stuffing bytes
*/

static bool get_pes_info(int pid, const unsigned char * pes_header, size_t pes_header_length,
		int * pes_packet_length, int * payload_offset,
		int * stream_id, int * sub_id, bool * pts_present, pts_t * pts)
{
	int pes_opt_header_length;

	if(pes_header_length < 8)
	{
		debug("invalid pes header, too short: %d bytes\n", (int)pes_header_length);
		return(false);
	}

	if((pes_header[0] != 0) || (pes_header[1] != 0) || (pes_header[2] != 1))
	{
		debug("pid %x: corrupt pes header, missing syncword\n", pid);
		return(false);
	}

	*stream_id			=	pes_header[3];
	*pes_packet_length	=	(pes_header[4] << 8) | pes_header[5];

	if(((pes_header[6] >> 6) & 0x03) != 0x02)
	{
		debug("pid %x: packet without optional pes header\n", pid);
		return(false);
	}

	pes_opt_header_length	=	pes_header[8];
	*payload_offset			=	pes_opt_header_length + 9;
	*sub_id					=	pes_header[*payload_offset];

	*pts_present = !!((pes_header[7] >> 7) & 0x01);

	if(pts_present)
		*pts = pes2pts(&pes_header[9]);
	else
		*pts = -1;

	return(true);
}

static bool process_pes_packet(FILE * out_z, FILE * out_nz, int pid, pts_t first_pts,
			unsigned char * pes_packet, int pes_packet_length_in,
			int * target_page, int target_data_unit)
{
	int						stream_id;
	int						payload_offset;
	int						sub_id;
	int						pes_packet_length;
	bool					pts_present;
	pts_t					pts;
	int						payload_index;
	int						data_unit_id;
	int						data_length;
	unsigned char			ttx_packet_0_header[4];
	int						line;

	unsigned char 			ttx_header[2];
	int						ttx_header_magazine;
	int						ttx_packet_id;

	static struct
	{
		int			page;
		int			subpage;
		int			flags;
		bool		erase_flag;
		ttx_page_t	page_buffer;
	} ttx_page_data /*= 
	{
		-1, -1, -1, 0, -1
	}*/;

	if(!get_pes_info(pid, pes_packet, pes_packet_length_in, 
			&pes_packet_length, &payload_offset, &stream_id, &sub_id,
			&pts_present, &pts))
	{
		warning("pid %x: pes packet corrupt, skipping\n", pid);
		return(false);
	}

	if(pes_packet_length_in != (pes_packet_length + 6))
	{
		warning("pid %x: corrupt pes packet: packet lengths differ: %d, %d\n",
					pid, pes_packet_length_in, pes_packet_length);
		return(false);
	}

	if((stream_id != 0xbd)) // || (sub_id < 0x10) || ((sub_id > 0x1f) && (sub_id != 0x99)))
	{
		error("pid %x: not a private data type 1 stream\n", pid);
		error("stream_id = %x, sub_id = %x\n", stream_id, sub_id);
		return(false);
	}

	if(!pts_present)
		warning("pid %x: no PTS present in pes packet\n", pid);

	/*
	 * pes teletext payload (payload_index) packet length = 44 + 2 = 46
	 *
	 * byte 0		data unit id / (0x02 = teletext, 0x03 = subtitling, 0xff = stuffing)
	 * byte 1		data length (0x2c = 44)
	 * byte 2		original screen line number
	 * byte 3		start byte = 0xe4
	 * byte 4-5		hammed header byte 1
	 * byte 6-45	text payload
	 */

	for(payload_index = payload_offset + 1; payload_index < pes_packet_length; )
	{
		data_unit_id	= pes_packet[payload_index + 0];
		data_length		= pes_packet[payload_index + 1];

		if(data_unit_id == 0xff) // stuffing
			goto skip;

		if(data_unit_id != target_data_unit)
			goto skip;

		if(data_length != 0x2c)
		{
			warning("data length != 0x2c: %x\n", data_length);
			data_length = 0x2c;
			goto skip;
		}

		bit_reverse(&pes_packet[payload_index + 2], data_length + 2 - 2);

		if(pes_packet[payload_index + 3] != 0x27)
		{
			warning("start code not found (= 0x%x), packet corrupt\n",
					pes_packet[payload_index + 3]);
			goto skip;
		}

		unham(&pes_packet[payload_index + 4], ttx_header, 2);

		ttx_header_magazine	= (ttx_header[0] & 0x07) >> 0;
		ttx_packet_id	= (ttx_header[0] & 0xf8) >> 3;

		if(ttx_header_magazine == 0)
			ttx_header_magazine = 8;

		if(ttx_packet_id == 0)
		{
			unham(&pes_packet[payload_index + 6], ttx_packet_0_header, 8);

			if(ttx_packet_0_header[0] != 0xff)
			{
				ttx_page_data.page = ttx2page(ttx_packet_0_header[0]);
				ttx_page_data.page += 100 * ttx_header_magazine;
			}

			ttx_page_data.subpage	= ((ttx_packet_0_header[2] << 8) | (ttx_packet_0_header[1])) & 0x3f7f;
			ttx_page_data.subpage	= ttx2page(ttx_page_data.subpage);

			ttx_page_data.flags	=	(ttx_packet_0_header[1] & 0x80) |
								((ttx_packet_0_header[3] << 4) & 0x10) |
								((ttx_packet_0_header[3] << 2) & 0x08) |
								((ttx_packet_0_header[3] >> 0) & 0x04) |
								((ttx_packet_0_header[3] >> 1) & 0x02) |
								((ttx_packet_0_header[3] >> 4) & 0x01);

			ttx_page_data.erase_flag = !!(ttx_page_data.flags & 0x80);

			if((ttx_page_data.page != 0) && (*target_page == -1))
			{
				debug("found teletext subtitling page: %d\n", ttx_page_data.page);
				*target_page = ttx_page_data.page;
			}

			if(ttx_page_data.page == *target_page)
			{
				const char * sub_line = 0;
				subtitle_t * sub;

				if(flag_view)
					view_page(pts, ttx_page_data.page,
							ttx_page_data.subpage, ttx_page_data.page_buffer);

				sub_line = page_to_line(ttx_page_data.page_buffer);
				sub	= make_sub(first_pts, pts, sub_line);
				push_sub(out_z, out_nz, sub);
			}

			for(line = 0; line < ttx_page_row_size; line++)
				memset(ttx_page_data.page_buffer[line], ' ', ttx_page_col_size);
		}

		if((ttx_packet_id > 0) && (ttx_packet_id < 24))
		{
			if(*target_page != -1)
			{
				remove_parity(&pes_packet[payload_index + 6], data_length + 2 - 6);
				memcpy(ttx_page_data.page_buffer[ttx_packet_id - 1], &pes_packet[payload_index + 6],
						ttx_page_col_size);
			}
		}
skip:
		payload_index += data_length + 2;
	}

	return(true);
}

static void debug_tsp(ts_pid_t ** pids, int count, int total_count)
{
	int			ix;
	ts_pid_t *	tsp;

	fprintf(stderr, "\npackets: %d, pids:\n", total_count);

	for(ix = 0; ix < count; ix++)
	{
		tsp = pids[ix];

		fprintf(stderr, "pid:%4.4x stream:%2.2x sub:%2.2x "
						"loc_cc:%2u rem_cc:%2u ignore:%s target:%s pkts:%d inval pes hdr:%d lost:%d nopayload:%d inval ts hdr:%d disc:%d skip:%d oversize:%d\n",
				tsp->pid, tsp->pes_stream_id & 0xff, tsp->pes_sub_id & 0xff,
				tsp->local_continuity_counter & 0x0f, tsp->remote_continuity_counter & 0x0f,
				tsp->ignore ? "yes" : "no",
				tsp->target ? "yes" : "no",
				tsp->counter, tsp->stat_invalid_pes_header, tsp->stat_lost,
				tsp->stat_nopayload, tsp->stat_invalid_header, tsp->stat_discard,
				tsp->stat_skipped, tsp->stat_payload_oversize);
	}

	fprintf(stderr, "\n");
}

static bool process_stream(FILE * in, FILE * out_z, FILE * out_nz, int target_pid, int target_page, int target_data_unit)
{
	unsigned char	ts_packet[188];
	size_t			ts_packet_length;
	bool			ts_packet_adaptation_field_present;
	bool			ts_packet_payload_present;
	bool			ts_packet_payload_start_indicator;
	int				ts_packet_payload_offset;
	int				ts_packet_payload_length;
	int				ts_packet_total_length;
	int				ts_packet_adaptation_field_length;
	bool			ts_packet_discontinuity_indicator;
	int				ts_packet_counter = 0;
	unsigned char *	ts_packet_pes_payload;

	int				pid;
	int				syncword;
	int				skipped_bytes;
	int				continuity_counter_dropped;
	bool			ts_new_pid;
	int				ix;
	pts_t			first_pts = -1;

	ts_pid_t **		ts_pids			= 0;
	size_t			ts_pids_alloc	= 0;
	size_t			ts_pids_offset	= 0;
	ts_pid_t *		ts_pid;

	for(;;)
	{
		syncword		= 0;
		skipped_bytes	= 0;

		while(syncword != 0x47)
			if((syncword = fgetc(in)) == EOF)
				goto eof;
			else
				skipped_bytes++;

		if(skipped_bytes > 1)
			warning("skipped %d bytes when searching for syncword\n", skipped_bytes);

		ts_packet_length = fread(&ts_packet[1], 1, sizeof(ts_packet) - 1, in);
		ts_packet[0] = syncword;

		if(ts_packet_length < 0)
		{
			error(strerror(errno));
			return(false);
		}

		ts_packet_length++;

		if(ts_packet_length != sizeof(ts_packet))
			goto eof;

		ts_packet_counter++;

		pid = (((ts_packet[1] & 0x1f) << 8) | ts_packet[2]);

		ts_pid = 0;

		for(ix = 0; ix < ts_pids_offset; ix++)
		{
			if(ts_pids[ix]->pid == pid)
			{
				ts_pid = ts_pids[ix];
				break;
			}
		}

		if(ts_pid)
			ts_new_pid = false;
		else
		{
			ts_new_pid = true;

			if((ts_pids_offset + 2) >= ts_pids_alloc)
			{
				ts_pids_alloc	+= 16;
				ts_pids			= (ts_pid_t **)realloc(ts_pids, sizeof(*ts_pids) * ts_pids_alloc);

				for(ix = ts_pids_offset; ix < ts_pids_alloc; ix++)
				{
					ts_pid = ts_pids[ix]				= (ts_pid_t *)malloc(sizeof(**ts_pids));
					ts_pid->pid							= -1;
					ts_pid->ignore						= false;
					ts_pid->target						= false;
					ts_pid->counter						= 0;
					ts_pid->local_continuity_counter	= -1;
					ts_pid->remote_continuity_counter	= -1;
					ts_pid->skip_to_pes_payload_start	= true;
					ts_pid->pes_payload_start			= 0;
					ts_pid->pes_payload_length			= 0;
					ts_pid->pes_stream_id				= -1;
					ts_pid->pes_sub_id					= -1;
					ts_pid->pts							= -1;

					ts_pid->payload_buffer				= 0;
					ts_pid->payload_offset				= 0;
					ts_pid->payload_alloc				= 0;

					ts_pid->stat_invalid_pes_header		= 0;
					ts_pid->stat_lost					= 0;
					ts_pid->stat_nopayload				= 0;
					ts_pid->stat_invalid_header			= 0;
					ts_pid->stat_discard				= 0;
					ts_pid->stat_skipped				= 0;
					ts_pid->stat_payload_oversize		= 0;
				}
			}

			ts_pid = ts_pids[ts_pids_offset++];
			ts_pid->pid = pid;

			if(pid == 0) // PAT
				ts_pid->ignore = true;
		}

		ts_pid->counter++;

		if((target_pid != -1) && (pid != target_pid))
			goto next_packet;

		if(flag_view)
		{
			char buffer[128];
			snprintf(buffer, sizeof(buffer), "%6d %4.4x %4.4x %6d              ",
				ts_packet_counter, pid, target_pid, ts_pid->counter);

			mvaddstr(0, 0, buffer);
			refresh();
		}

		/*
		 * ts packet layout
		 *
		 * byte	0		0x47
		 * byte 1-2		transport error indicator (1 bit), payload unit start indicator (1 bit), transport prio (1 bit), pid (13 bits)
		 * byte 3		scrambling control (2 bits), adaptation field indicator (1 bit), payload indicator (1 bit), continuity counter (4 bits)
		 * byte 4		adaptation field length
		 * byte 5		discontinuity indicator, random access indicator, pes priority ind, pcr flag, opcr flag,
		 * 				splicing point flag, transport private data flag, adaptation field extension flag
		 * byte 6		pcr / splice countdown / stuffing bytes / payload
		 * 
		 */

		ts_packet_payload_start_indicator	= !!(ts_packet[1] & 0x40);
		ts_packet_adaptation_field_present	= !!(ts_packet[3] & 0x20);
		ts_packet_payload_present			= !!(ts_packet[3] & 0x10);

		if(ts_packet_adaptation_field_present)
		{
			ts_packet_adaptation_field_length = ts_packet[4];
			ts_packet_discontinuity_indicator = !!(ts_packet[5] & 0x80);
		}
		else
		{
			ts_packet_adaptation_field_length = 0;
			ts_packet_discontinuity_indicator = false;
		}

		ts_pid->remote_continuity_counter	= ts_packet[3] & 0x0f;

		ts_packet_payload_offset	= 4 + ts_packet_adaptation_field_length + (ts_packet_adaptation_field_present ? 1 : 0);
		ts_packet_payload_length	= sizeof(ts_packet) - ts_packet_payload_offset;
		ts_packet_total_length		= 4 + ts_packet_adaptation_field_length + (ts_packet_adaptation_field_present ? 1 : 0) + ts_packet_payload_length;
	
		if(flag_hexdump && !ts_pid->ignore)
		{
			debug("\n*** new packet in pid %x ***\n", pid);
			hexdump(ts_packet, sizeof(ts_packet), ts_packet_payload_offset);
			debug("payload present              is%sset\n", ts_packet_payload_present ? " " : " not ");
			debug("payload unit start indicator is%sset\n", ts_packet_payload_start_indicator ? " " : " not ");
			debug("adaptation field present     is%sset\n", ts_packet_adaptation_field_present ? " " : " not ");
			debug("local continuity counter     is %d\n",   ts_pid->local_continuity_counter);
			debug("remote continuity counter    is %d\n",   ts_pid->remote_continuity_counter);
			debug("transport error indicator    is%sset\n", ts_packet[1] & 0x80 ? " " : " not ");
			debug("discontinuity indicator      is%sset\n", ts_packet_discontinuity_indicator ? " " : " not ");
			debug("adaptation field length      is %d\n", ts_packet_adaptation_field_length);
			debug("payload offset               is %d\n", ts_packet_payload_offset);
			debug("payload length               is %d\n", ts_packet_payload_length);
			debug("total packet length          is %d\n", ts_packet_total_length);
			debug("\n");
		}

		if(ts_pid->local_continuity_counter == -1)
			ts_pid->local_continuity_counter = ts_pid->remote_continuity_counter;
		else
		{
			if(ts_packet_payload_present)
			{
				ts_pid->local_continuity_counter++;
				ts_pid->local_continuity_counter %= 16;
			}
		}

		if(ts_pid->local_continuity_counter != ts_pid->remote_continuity_counter)
		{
			if(!ts_packet_discontinuity_indicator)
			{
				continuity_counter_dropped =
					(ts_pid->remote_continuity_counter + 16 - ts_pid->local_continuity_counter) % 16;
				warning("pid %x: lost %d ts packets\n", pid, continuity_counter_dropped);
				ts_pid->stat_lost++;
				ts_pid->skip_to_pes_payload_start = true;
				ts_pid->payload_offset = 0;
				ts_new_pid = true;
				ts_pid->local_continuity_counter = ts_pid->remote_continuity_counter;

				goto next_packet;
			}

			ts_pid->local_continuity_counter = ts_pid->remote_continuity_counter;
		}

		if(ts_packet_adaptation_field_length > 183)
		{
			warning("pid %x: adaptation field_length > ts packet size, dropping pes packet\n", pid);
			ts_pid->stat_invalid_header++;
			ts_pid->skip_to_pes_payload_start = true;
			ts_pid->payload_offset = 0;
			ts_new_pid = true;
			goto next_packet;
		}

		if(!ts_packet_payload_present)
		{
			debug("pid %x: discarding packet without payload\n", pid);
			ts_pid->stat_nopayload++;
			goto next_packet;
		}

		ts_packet_pes_payload = &ts_packet[ts_packet_payload_offset];

		if(ts_pid->ignore)
			goto next_packet;

		if(ts_packet_payload_start_indicator)
		{
			bool pts_present;

			if(ts_pid->pes_payload_length != 0)
			{
				warning("pid %x: discarding %d bytes from open pes packet (2)\n", pid, ts_pid->pes_payload_length);
				ts_pid->stat_discard++;
				ts_pid->pes_payload_length	= 0;
				ts_pid->payload_offset		= 0;
			}

			if(!get_pes_info(pid, ts_packet_pes_payload, ts_packet_payload_length,
					&ts_pid->pes_payload_length, &ts_pid->pes_payload_start,
					&ts_pid->pes_stream_id, &ts_pid->pes_sub_id, &pts_present, &ts_pid->pts))
			{
				debug("pid %x: invalid pes header, skip pes packet\n", pid);
				ts_pid->stat_invalid_pes_header++;
				ts_pid->skip_to_pes_payload_start = true;
				ts_pid->payload_offset = 0;
				ts_new_pid = true;
				goto next_packet;
			}

			if((first_pts == -1) && (pts_present))
				first_pts = ts_pid->pts;

			if((ts_pid->pes_stream_id == 0xbd) && ((ts_pid->pes_sub_id >= 0x10) || (ts_pid->pes_sub_id <= 0x1f)))
			{
				if(!ts_pid->target)
				{
					debug("pid %x: found teletext stream\n", pid);
					target_pid = pid;
					ts_pid->target = true;
				}
			}
			else
			{
				debug("pid %x: no teletext stream\n", pid);

				if(first_pts != -1)
					ts_pid->ignore = true;

				ts_new_pid = true;
				goto next_packet;
			}

			ts_pid->pes_payload_length += 6; // add pes header bytes
			ts_pid->skip_to_pes_payload_start = false;
		}
		else
		{
			if(ts_pid->skip_to_pes_payload_start)
			{
				ts_pid->stat_skipped++;
				goto next_packet;
			}
		}

		if(target_pid != -1)
		{
			if((ts_pid->payload_offset + ts_packet_payload_length + 2) > ts_pid->payload_alloc)
			{
				ts_pid->payload_alloc += 256;
				ts_pid->payload_buffer = (unsigned char *)realloc(ts_pid->payload_buffer, ts_pid->payload_alloc);
			}

			memcpy(&ts_pid->payload_buffer[ts_pid->payload_offset], ts_packet_pes_payload, ts_packet_payload_length);
		}

		ts_pid->payload_offset += ts_packet_payload_length;

		if(ts_pid->payload_offset > ts_pid->pes_payload_length)
		{
			warning("pid %x: payload of pes larger than payload length in pes header\n", pid);
			ts_pid->stat_payload_oversize++;
			ts_pid->payload_offset = ts_packet_payload_length;
		}

		if(ts_pid->payload_offset == ts_pid->pes_payload_length)
		{
			if(target_pid != -1)
				process_pes_packet(out_z, out_nz, pid, first_pts, ts_pid->payload_buffer, ts_pid->payload_offset,
						&target_page, target_data_unit);

			ts_pid->payload_offset		= 0;
			ts_pid->pes_payload_length	= 0;
		}

next_packet:
		if(flag_debug && !flag_view && ts_new_pid)
			debug_tsp(ts_pids, ts_pids_offset, ts_packet_counter);
	}

eof:
	if(flag_debug && !flag_view)
		debug_tsp(ts_pids, ts_pids_offset, ts_packet_counter);

	return(true);
}

static void usage()
{
	fprintf(stderr, "usage: dvb2srt [-a] [-d] [-h] [-v] [-c]\n"
					"        [-s offset] [-u data_unit_id] [-p pid] [-P page]\n"
					"        [-o output file] [-z outputfile] infile\n"
					"        -o output file (original timestamps)\n"
					"        -z output file (timestamps starting from zero)\n"
					"        -d debug, -h hexdump, -a do not use ssa subs, use srt\n"
					"        -s timestamp skew (for out of sync subtitles),\n"
					"        -v view teletext pages as they come by\n");
	exit(-1);
}

static void ssa_header(FILE * fp)
{
	fprintf(fp, "[Script Info]\n"
			"Title: dvb2srt\n"
 			"Original Script: dvb2srt\n"
 			"Script Updated By: none\n"
 			"ScriptType: v4.00\n"
 			"Collisions: Normal\n"
 			"PlayResX: 600\n"
 			"PlayResY: 600\n"
 			"PlayDepth: 1\n"
 			"Timer: 100,0000\n"
  			"\n"
 			"[V4 Styles]\n"
 			"Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, TertiaryColour, BackColour, Bold, Italic, BorderStyle, Outline, Shadow, "
    		"Alignment, MarginL, MarginR, MarginV\n"
			"Style: default, DejaVu Sans, 18, 16777215, 16777215, 16777215, 0, 0, 0, 1, 1, 1, 2, 20, 20, 4\n"
 			"\n"
 			"[Events]\n"
 			"Format: Marked, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text\n");
}

int main(int argc, char** argv)
{
	FILE *			in;
	FILE *			out_z				= 0;
	FILE *			out_nz				= 0;
	int				opt;
	int				target_pid			= -1;
	int				target_page			= -1;
	int				target_data_unit	= 3;
	WINDOW *		curses_window;

	while((opt = getopt(argc, argv, "acdhvp:P:u:t:o:z:s:")) != -1)
	{
		switch(opt)
		{
			case('a'):
			{
				flag_ssa = !flag_ssa;
				break;
			}

			case('c'):
			{
				flag_compress = !flag_compress;
				break;
			}

			case('d'):
			{
				flag_debug = !flag_debug;
				break;
			}

			case('h'):
			{
				flag_hexdump = !flag_hexdump;
				break;
			}

			case('o'):
			{
				if(!(out_nz = fopen(optarg, "w")))
				{
					perror("open output file");
					exit(-1);
				}
				break;
			}

			case('p'):
			{
				target_pid	= strtol(optarg, 0, 0);
				break;
			}

			case('s'):
			{
				long double offset;

				offset = strtold(optarg, 0);

				if(offset == 0)
				{
					fprintf(stderr, "option -s requires the offset in seconds (+fraction) as argument\n");
					exit(-1);
				}

				option_offset = offset * -90000;

				break;
			}

			case('u'):
			{
				target_data_unit = strtol(optarg, 0, 0);
				break;
			};

			case('v'):
			{
				flag_view = !flag_view;
				break;
			}


			case('z'):
			{
				if(!(out_z = fopen(optarg, "w")))
				{
					perror("open output file");
					exit(-1);
				}
				break;
			}

			case('P'):
			{
				target_page	= strtol(optarg, 0, 0);
				break;
			};

			default:
			{
				usage();
			}
		}
	}

	if((argc - optind) < 1)
	{
		fprintf(stderr, "missing input file\n");
		usage();
	}

	if(!(in = fopen(argv[optind + 0], "r")))
	{
		fprintf(stderr, "cannot open input file \"%s\"\n", argv[optind + 0]);
		exit(-1);
	}

	if(!out_z)
		out_z = fopen("/dev/null", "w");

	if(!out_nz)
		out_nz = fopen("/dev/null", "w");

	if(!out_z || !out_nz)
	{
		perror("open /dev/null");
		exit(-1);
	}
	
	if(flag_view)
		curses_window = initscr();

	if(flag_ssa)
	{
		ssa_header(out_z);
		ssa_header(out_nz);
	}

	process_stream(in, out_z, out_nz, target_pid, target_page, target_data_unit);

	if(flag_view)
		endwin();

	fclose(in);
	fclose(out_z);
	fclose(out_nz);

	return(0);
}
