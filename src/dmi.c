/*
    Copyright 2023 Quectel Wireless Solutions Co.,Ltd

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>

extern FILE *log_fp;
const char *get_time(void);

#define debug(fmt, args...) do { \
	if (log_fp) fprintf(log_fp, "[%s] " fmt "\n", get_time(), ##args); \
} while (0)

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef struct {
	u32 l;
	u32 h;
} u64;

#define WORD(x) (u16)(*(const u16 *)(x))
#define DWORD(x) (u32)(*(const u32 *)(x))
#define QWORD(x) (*(const u64 *)(x))

#define out_of_spec "<OUT OF SPEC>"
static const char *bad_index = "<BAD INDEX>";

#define SUPPORTED_SMBIOS_VER 0x030300

#define FLAG_NO_FILE_OFFSET     (1 << 0)
#define FLAG_STOP_AT_EOT        (1 << 1)

#define SYS_ENTRY_FILE "/sys/firmware/dmi/tables/smbios_entry_point"
#define SYS_TABLE_FILE "/sys/firmware/dmi/tables/DMI"
#define DEFAULT_MEM_DEV "/dev/mem"

#define LENOVO_SMBIOS_OEM_TYPE 0x85
#define LENOVO_SMBIOS_OEM_LENGTH 0x05
static const char lenovo_fcc_string[] = "KHOIHGIUCCHHII";

struct dmi_header
{
	u8 type;
	u8 length;
	u16 handle;
	u8 *data;
};

struct opt
{
	const char *devmem;
	unsigned int flags;
	u8 type;
	u32 handle;
	const char *oem_string;
};
static struct opt opt;

int checksum(const u8 *buf, size_t len)
{
	u8 sum = 0;
	size_t a;

	for (a = 0; a < len; a++)
		sum += buf[a];
	return (sum == 0);
}

static int myread(int fd, u8 *buf, size_t count, const char *prefix)
{
	ssize_t r = 1;
	size_t r2 = 0;

	while (r2 != count && r != 0)
	{
		r = read(fd, buf + r2, count - r2);
		if (r == -1)
		{
			if (errno != EINTR)
			{
				close(fd);
				perror(prefix);
				return -1;
			}
		}
		else
			r2 += r;
	}

	if (r2 != count)
	{
		close(fd);
		fprintf(stderr, "%s: Unexpected end of file\n", prefix);
		return -1;
	}

	return 0;
}

void *read_file(off_t base, size_t *max_len, const char *filename)
{
	struct stat statbuf;
	int fd;
	u8 *p;

	/*
	 * Don't print error message on missing file, as we will try to read
	 * files that may or may not be present.
	 */
	if ((fd = open(filename, O_RDONLY)) == -1)
	{
		if (errno != ENOENT)
			perror(filename);
		return NULL;
	}

	/*
	 * Check file size, don't allocate more than can be read.
	 */
	if (fstat(fd, &statbuf) == 0)
	{
		if (base >= statbuf.st_size)
		{
			fprintf(stderr, "%s: Can't read data beyond EOF\n",
				filename);
			p = NULL;
			goto out;
		}
		if (*max_len > (size_t)statbuf.st_size - base)
			*max_len = statbuf.st_size - base;
	}

	if ((p = malloc(*max_len)) == NULL)
	{
		perror("malloc");
		goto out;
	}

	if (lseek(fd, base, SEEK_SET) == -1)
	{
		fprintf(stderr, "%s: ", filename);
		perror("lseek");
		goto err_free;
	}

	if (myread(fd, p, *max_len, filename) == 0)
		goto out;

err_free:
	free(p);
	p = NULL;

out:
	if (close(fd) == -1)
		perror(filename);

	return p;
}

/* Replace non-ASCII characters with dots */
static void ascii_filter(char *bp, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
	{
		if (bp[i] < 32 || bp[i] == 127)
		{
			bp[i] = '.';
		}
	}

}

static char *_dmi_string(const struct dmi_header *dm, u8 s, int filter)
{
	char *bp = (char *)dm->data;

	bp += dm->length;
	while (s > 1 && *bp)
	{
		bp += strlen(bp);
		bp++;
		s--;
	}

	if (!*bp)
		return NULL;

	if (filter)
		ascii_filter(bp, strlen(bp));

	return bp;
}

const char *dmi_string(const struct dmi_header *dm, u8 s)
{
	char *bp;

	if (s == 0)
		return "Not Specified";

	bp = _dmi_string(dm, s, 1);
	if (bp == NULL)
		return bad_index;

	return bp;
}

const char *dmi_oem_string(const struct dmi_header *h)
{
	u8 *p = h->data + 4;
	u8 count = p[0x00];
	int i;

	for (i = 1; i <= count; i++)
	{
		const char *oem_string = NULL;
		debug("String %hu", i);
		oem_string = dmi_string(h, i);
		debug("%s", oem_string);
		if (oem_string && !strcmp(oem_string, lenovo_fcc_string))
			opt.oem_string = lenovo_fcc_string;
	}

	return NULL;
}

static void dmi_decode(const struct dmi_header *h, u16 ver)
{
	if (h->type == opt.type) {
		debug("Handle 0x%04X, DMI type %d, %d bytes", h->handle, h->type, h->length);
		dmi_oem_string(h);
	}	
}

static void to_dmi_header(struct dmi_header *h, u8 *data)
{
	h->type = data[0];
	h->length = data[1];
	h->handle = WORD(data + 2);
	h->data = data;
}

static void dmi_table_decode(u8 *buf, u32 len, u16 num, u16 ver, u32 flags)
{
	u8 *data;
	int i = 0;

	data = buf;
	while ((i < num || !num)
	    && data + 4 <= buf + len) /* 4 is the length of an SMBIOS structure header */
	{
		u8 *next;
		struct dmi_header h;

		to_dmi_header(&h, data);

		if (h.length < 4)
		{
			fprintf(stderr,
				    "Invalid entry length (%u). DMI table "
				    "is broken! Stop.\n\n",
				    (unsigned int)h.length);
			break;
		}
		i++;

		/* Look for the next handle */
		next = data + h.length;
		while ((unsigned long)(next - buf + 1) < len && (next[0] != 0 || next[1] != 0))
		{
            next++;
        }
		next += 2;

		/* Make sure the whole structure fits in the table */
		if ((unsigned long)(next - buf) > len)
		{
			debug("<TRUNCATED>");
			data = next;
			break;
		}

		dmi_decode(&h, ver);

		data = next;
	}
}

static void dmi_table(off_t base, u32 len, u16 num, u32 ver, const char *devmem,
		      u32 flags)
{
	u8 *buf;
	size_t size = len;

	if (ver > SUPPORTED_SMBIOS_VER)
	{
		debug("SMBIOS implementations newer than version %u.%u.%u are not fully supported by this version of dmidecode.",
			   SUPPORTED_SMBIOS_VER >> 16,
			   (SUPPORTED_SMBIOS_VER >> 8) & 0xFF,
			   SUPPORTED_SMBIOS_VER & 0xFF);
	}

	debug("Table at 0x%08llX.", (unsigned long long)base);

	buf = read_file(flags & FLAG_NO_FILE_OFFSET ? 0 : base, &size, devmem);
	len = size;

	if (buf == NULL)
	{
		fprintf(stderr, "Failed to read table, sorry.\n");
		return;
	}

	// coverity[tainted_data:FALSE]
	dmi_table_decode(buf, len, num, ver >> 8, flags);
	free(buf);
}

static int smbios3_decode(u8 *buf, const char *devmem, u32 flags)
{
	u32 ver;
	u64 offset;

	/* Don't let checksum run beyond the buffer */
	if (buf[0x06] > 0x20)
	{
		fprintf(stderr,
			    "Entry point length too large (%u bytes, expected %u).\n",
			    (unsigned int)buf[0x06], 0x18U);
		return 0;
	}

	if (!checksum(buf, buf[0x06]))
		return 0;

	ver = (buf[0x07] << 16) + (buf[0x08] << 8) + buf[0x09];
	debug("SMBIOS %u.%u.%u present.", buf[0x07], buf[0x08], buf[0x09]);

	offset = QWORD(buf + 0x10);
	dmi_table(((off_t)offset.h << 32) | offset.l,
		  DWORD(buf + 0x0C), 0, ver, devmem, flags | FLAG_STOP_AT_EOT);

	return 1;
}

const char *dmidecode_query_lenovo_fcc_string(void)
{
	u8 *buf;
	size_t size;

	/* Set default option values */
	opt.devmem = DEFAULT_MEM_DEV;
	opt.flags = 0;
	opt.handle = ~0u;
	opt.type = LENOVO_SMBIOS_OEM_TYPE;
	opt.oem_string = NULL;

	size = 0x20;
	buf = read_file(0, &size, SYS_ENTRY_FILE);
	if (buf != NULL)
	{
		if (size >= 24 && memcmp(buf, "_SM3_", 5) == 0)
		{
			smbios3_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET);
		}
		free(buf);
	}

	return opt.oem_string;
}