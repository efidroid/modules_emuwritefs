/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This file system mirrors the existing file system hierarchy of the
 * system, starting at the root file system. This is implemented by
 * just "passing through" all requests to the corresponding user-space
 * libc functions. This implementation is a little more sophisticated
 * than the one in passthrough.c, so performance is not quite as bad.
 *
 * Compile with:
 *
 *     gcc -Wall passthrough_fh.c `pkg-config fuse3 --cflags --libs` -lulockmgr -o passthrough_fh
 *
 * ## Source code ##
 * \include passthrough_fh.c
 */

#define FUSE_USE_VERSION 30

#define _GNU_SOURCE

#include <fuse.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <private/list.h>

#include <lib/emuwritefs.h>

#define ROUNDDOWN(a, b) ((a) & ~((b)-1))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

typedef struct {
    list_node_t node;

    off_t index;
    void* data;
} memblock_t;

typedef struct {
    list_node_t node;

    int srcfd;
    char* pathname;
    struct stat stbuf;

    size_t memblocksz;
    list_node_t memblocks;
} fnode_t;

typedef struct {
    int fd;
    fnode_t *node;
} fhandle_t;

typedef struct {
  list_node_t nodes;
} pdata_t;

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi);

static inline fhandle_t *get_fhandle(struct fuse_file_info *fi)
{
	return (fhandle_t *) (uintptr_t) fi->fh;
}

static inline pdata_t *get_pdata(void)
{
	return (pdata_t *) fuse_get_context()->private_data;
}

static int get_blocksz(int fd, off_t *psize) {
    unsigned long numblocks;
    if (ioctl(fd, BLKGETSIZE, &numblocks) == -1)
        return -1;

    *psize = numblocks*512;

    return 0;
}

int emuwritefs_add_node(void* handle, const char* pathname, const char* srcfile)
{
    pdata_t* pdata = (pdata_t*) handle;
    fnode_t *node = calloc(1, sizeof(fnode_t));
    if (!node)
        return -ENOMEM;
    list_initialize(&node->memblocks);
    node->memblocksz = 4096;

    // open file
    int rc = open(srcfile, O_RDONLY);
    if (rc < 0) {
        free(node);
        return rc;
    }
    node->srcfd = rc;

    // build stat structure
    node->stbuf.st_mode = S_IFREG | 0444;
    node->stbuf.st_nlink = 1;

    // get file/blockdev size
    rc = get_blocksz(node->srcfd, &node->stbuf.st_size);
    if (rc) {
        struct stat st;
        rc = fstat(node->srcfd, &st);
        if (rc) {
            close(node->srcfd);
            free(node);
            return rc;
        }

        node->stbuf.st_size = st.st_size;
    }

    // store pathname
    size_t pathname_len = strlen(pathname)+2;
    node->pathname = malloc(pathname_len);
    if (!node->pathname) {
        close(node->srcfd);
        free(node);
        return -ENOMEM;
    }
    snprintf(node->pathname, pathname_len, "%s%s", pathname[0]=='/'?"":"/", pathname);

    list_add_tail(&pdata->nodes, &node->node);

    return 0;
}

static fnode_t* get_node(pdata_t *pdata, const char* pathname) {
    fnode_t *node;
    list_for_every_entry(&pdata->nodes, node, fnode_t, node) {
        if (!strcmp(node->pathname, pathname))
            return node;
    }

    return NULL;
}

static inline memblock_t *get_memblock_by_index(fhandle_t* fh, off_t index)
{
    memblock_t *memblock;
    list_for_every_entry(&fh->node->memblocks, memblock, memblock_t, node) {
        if (memblock->index == index)
            return memblock;
    }

    return NULL;
}

static void* get_blockbuf(fhandle_t* fh, off_t offset, size_t* psize, int create) {
    off_t offset_rounddown = ROUNDDOWN(offset, fh->node->memblocksz);
    off_t blockid = offset_rounddown/fh->node->memblocksz;
    off_t block_offset = offset - offset_rounddown;

    memblock_t *memblock = get_memblock_by_index(fh, blockid);
    if (!memblock) {
        if(!create) {
            return NULL;
        }

        memblock = malloc(sizeof(*memblock));
        if(!memblock)
            return NULL;
        memblock->data = malloc(fh->node->memblocksz);
        if(!memblock->data) {
            free(memblock);
            return NULL;
        }
        memblock->index = blockid;

        ssize_t num_bytes = pread(fh->fd, memblock->data, fh->node->memblocksz, offset_rounddown);
        if(num_bytes<0) {
            free(memblock->data);
            free(memblock);
            return NULL;
        }

        list_add_tail(&fh->node->memblocks, &memblock->node);
    }

    *psize = fh->node->memblocksz-block_offset;
    return memblock->data + block_offset;
}

static void *xmp_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;
	cfg->nullpath_ok = 1;

	return get_pdata();
}

static int xmp_getattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi)
{
    pdata_t *pdata = get_pdata();

    if (fi) {
        fhandle_t *fh = get_fhandle(fi);
        memcpy(stbuf, &fh->node->stbuf, sizeof(*stbuf));
        return 0;
    }

    if (!strcmp(path, "/")) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    fnode_t *node = get_node(pdata, path);
    if (node) {
        memcpy(stbuf, &node->stbuf, sizeof(*stbuf));
        return 0;
    }

    return -ENOENT;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;
	(void) path;

    pdata_t *pdata = get_pdata();

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

    fnode_t *node;
    list_for_every_entry(&pdata->nodes, node, fnode_t, node) {
    	filler(buf, node->pathname+1, NULL, 0, 0);
    }

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
    pdata_t *pdata = get_pdata();

    fhandle_t *fh = malloc(sizeof(fhandle_t));
    if (fh == NULL)
	    return -ENOMEM;

    // get node
    fnode_t *node = get_node(pdata, path);
    if (!node) {
        free(fh);
        return -ENOENT;
    }
    fh->node = node;

    // dup fd
    fd = dup(node->srcfd);
	if (fd < 0) {
        free(fh);
		return -errno;
    }
	fh->fd = fd;

    // return file handle
    fi->fh = (uintptr_t)fh;

	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int res = 0;
    fhandle_t *fh = get_fhandle(fi);
	(void) path;

    while (size) {
        size_t membufsz;
        size_t readsize = 0;
        void *membuf = get_blockbuf(fh, offset, &membufsz, 0);
        if(!membuf) {
            off_t offset_rounddown = ROUNDDOWN(offset, fh->node->memblocksz);
            off_t block_offset = offset - offset_rounddown;

            readsize = MIN(size, fh->node->memblocksz-block_offset);
            ssize_t num_bytes = pread(fh->fd, buf, readsize, offset);
            if (num_bytes<0)
                return num_bytes;
        }
        else {
            readsize = MIN(size, membufsz);
            memcpy(buf, membuf, readsize);
        }

        buf += readsize;
        size -= readsize;
        offset += readsize;
        res += readsize;
    }

	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res = 0;
    fhandle_t *fh = get_fhandle(fi);
    (void) path;

    while (size) {
        size_t membufsz;
        void *membuf = get_blockbuf(fh, offset, &membufsz, 1);
        if(!membuf) {
            return -EIO;
        }

        size_t writesize = MIN(size, membufsz);
        memcpy(membuf, buf, writesize);
        buf += writesize;
        size -= writesize;
        offset += writesize;
        res += writesize;
    }

	return res;
}

static int xmp_flush(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	(void) fi;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
    fhandle_t *fh = get_fhandle(fi);
	close(fh->fd);
    free(fh);

	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	(void) path;
	(void) isdatasync;
	(void) fi;

	return 0;
}

static struct fuse_operations xmp_oper = {
	.init           = xmp_init,
	.getattr	= xmp_getattr,
	.readdir	= xmp_readdir,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.flush		= xmp_flush,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
};

void *emuwritefs_create_handle(void)
{
    pdata_t *pdata = calloc(1, sizeof(pdata_t));
    list_initialize(&pdata->nodes);
    return pdata;
}

int emuwritefs_main(void *handle, const char *mountpoint)
{
    const char* argv[] = {
        "emuwritefs",
        mountpoint
    };

	umask(0);
    optind = 1;
    opterr = 1;
    optopt = '?';
	return fuse_main_real(2, (char**)argv, &xmp_oper, sizeof(xmp_oper), handle);
}
