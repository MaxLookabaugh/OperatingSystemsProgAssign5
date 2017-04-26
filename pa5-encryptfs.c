/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

//need to define encrypted, decrypted and neither
#define ENCRYPT 1
#define DECRYPT 0
#define PASSTHROUGH -1
#define MAX_SIZE 1024
//include limits for realpath
#include <limits.h>
#include<fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
//include aes-cryot for do_crypt
#include "aes-crypt.h"

#define XATTR_ENCRYPTED "true"
#define XATTR_UNENCRYPTED "false"
#define XATTR_NAME "user.pa4-encryptfs.encrypted"

//global variables
char *PATH[1024];
char *KEYPHRASE[1024];

//struct for private data,
typedef struct encryptfs_vars encryptfs_vars;
struct encryptfs_vars {
	char* keyPhrase;
	char* rootPath;	

};

//get the ful path of fuse fs. 
void getFullPath(char* filepath, const char* path){
	//get the private data of the fs(in this case we want rootpath) 
	//This creates object with the data of the filesystem
	encryptfs_vars *data =(encryptfs_vars *) ( fuse_get_context() -> private_data);
	//copy the rootpath of the filesystem to new path
	strcpy(filepath, data->rootPath);
	//need to root path to path of current file
	strncat(filepath, path, 1024); 
	
}


int checkEncryption(char* filepath){
	int length;
	length = lgetxattr(filepath, XATTR_NAME, NULL, 0);
	if (length < 0) return 0;
	char value[length];
	lgetxattr(filepath, XATTR_NAME, value, length);
/*	if (strcmp(value, XATTR_ENCRYPTED)){ 
		return 0;
	}
	else{
		return 1;
	}
*/
 	return(!strcmp(value, XATTR_ENCRYPTED))? 1 : 0;


}


static int encryptfs_getattr(const char *path, struct stat *stbuf)
{
	int res;
	//set the filepath to PATH
	char filepath[1024];
//	encryptfs_vars data = fuse_get_context() -> private_data;
	getFullPath(filepath, path);
	//filepath = PATH;
	//lstat takes file at filepath and fills in stbuf
	res = lstat(filepath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_access(const char *path, int mask)
{
	int res;
	//assign filepath
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);
	res = access(filepath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_readlink(const char *path, char *buf, size_t size)
{
	int res;
	
	//assign filepath
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);
	
	res = readlink(filepath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int encryptfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);
	dp = opendir(filepath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int encryptfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	//adding filepath 
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(filepath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(filepath, mode);
	else
		res = mknod(filepath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_mkdir(const char *path, mode_t mode)
{
	int res;
	//adding file path
	char filepath[1024];
	//filepath = PATH;	
	getFullPath(filepath, path);
	
	res = mkdir(filepath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_unlink(const char *path)
{
	int res;
	//adding file path
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);

	res = unlink(filepath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_rmdir(const char *path)
{
	int res;
	//adding file path 
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);
	
	res = rmdir(filepath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_symlink(const char *from, const char *to)
{
	int res;
	//adding file system
	char filepathTo[1024];
	char filepathFrom[1024];
	getFullPath(filepathFrom, from);
	getFullPath(filepathTo, to);
	
	res = symlink(filepathFrom, filepathTo);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_rename(const char *from, const char *to)
{
	int res;
	//adding file system
	char filepathFrom[1024];
	char filepathTo[1024];
	getFullPath(filepathFrom, from);
	getFullPath(filepathTo, to);
		
	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_link(const char *from, const char *to)
{
	int res;
	char filepathFrom[1024];
	char filepathTo[1024];
	getFullPath(filepathFrom, from);
	getFullPath(filepathTo, to);

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_chmod(const char *path, mode_t mode)
{
	int res;
	//adding file path
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);
	
	res = chmod(filepath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	//addinh file path
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);

	res = lchown(filepath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_truncate(const char *path, off_t size)
{
	int res;

	//adding file path
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);	
	res = truncate(filepath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	//adding file path
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);
	
	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(filepath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	//adding filepath
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);	
	res = open(filepath, fi->flags);
	if (res == -1)
		return -errno;
	close(res);
	return 0;
}

static int encryptfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	
	int OPERATION;
	//NEED TO: copy the path not overwrite, and append new path to origin
	char filepath[1024];
	getFullPath(filepath, path);
	FILE* readFile;
	//get the data fron the filesystem
	encryptfs_vars* readData = (encryptfs_vars *)(fuse_get_context() -> private_data);
	char* encryptKey = readData -> keyPhrase;

	//need temp memfiles for open_memstream
	FILE* tmpFile;
	char* tmpStart;
	size_t tmpSize;	

	//int fd;
	int res;

	//OPERATION = checkEncryption(filepath);
	(void) fi;
	//test for open (make sure file can open)
/*	fd = open(path, O_RDONLY);
	//error conditions for read
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;
	

	close(fd);*/
	OPERATION = (checkEncryption(filepath))? DECRYPT : PASSTHROUGH;
	//can open file based on error conditions so open with fopen
	readFile = fopen(filepath, "rb");
	//open_memstream(bufferPtr, sizeOf); create IOstream with dynamically allocated buffer
	tmpFile = open_memstream(&tmpStart, &tmpSize);
	//decrypt on new file, pipe output to tmpFile
	do_crypt(readFile, tmpFile, OPERATION, encryptKey);
	//need to read file in npw that decrypted
	fseeko(tmpFile, offset, SEEK_SET);
	int csize = sizeof(char);
	res = csize * fread(buf, csize, size, tmpfile);
	//res = pread(tmpFile, buf, size, offset);
//possibly done with read?

//need fclose?
	//fclose(tmpFile);
	return res;
}

static int encryptfs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int OPERATION;
	char filepath[1024];
	//strcpy(filepath, PATH);
	//strncat(filepath, path, 1024);
	//similar to read need same temp files and variables
	getFullPath(filepath, path);
	FILE* writeFile;
	//char* encryptKey = KEYPHRASE;
	encryptfs_vars* writeData = (encryptfs_vars *)(fuse_get_context() -> private_data);
	char* encryptKey = writeData -> keyPhrase;

	char* tmpStart;
	FILE* tmpFile;
	size_t tmpSize;
	
	//int fd;
	int res;
	

	(void) fi;
	(void) offset;
	/*fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;
	
	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;
	
	close(fd);*/
	
	OPERATION = (checkEncryption(filepath))? ENCRYPT : PASSTHROUGH;
	//convert to stream	
	tmpFile = open_memstream(&tmpStart, &tmpSize);
	fwrite(buf, size, sizeof(char), tmpFile);
	//encrypt and read stream to the file
	writeFile = fopen(filepath, "rw+");	
	do_crypt(tmpFile, writeFile, OPERATION, encryptKey);
	fclose(writeFile);

	res = size;
	return res;
	//done reading from writeFile
	//fclose(writeFile);
	//now need to set offset: fseek on memfile to offset use SEEK_SET to offset from 
	//beggining of file
/*
	fseek(tmpFile, offset, SEEK_SET);
	//set result 
	res = fwrite(buf, 1, size, tmpFile);
	//now need to encrypt
	writeFile = fopen(filepath, "w");
	fseek(tmpFile, 0, SEEK_SET);
	do_crypt(tmpFile, writeFile, OPERATION, encryptKey);
	fclose(tmpFile);
	fclose(writeFile);
	//res = pwrite(tmpFile, buf, size, offset);
*/
	return res;
}

static int encryptfs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	
	char filepath[1024];
	strcpy(filepath, *PATH);
	strncat(filepath, path, 1024); 
	
	res = statvfs(filepath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encryptfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
	char filepath[1024];
	strcpy(filepath, *PATH);
	strncat(filepath, path, 1024);
    
	int res;
    res = creat(filepath, mode);
    if(res == -1)
	return -errno;

    close(res);
	
	res = lsetxattr(filepath, XATTR_NAME, XATTR_ENCRYPTED, sizeof(XATTR_ENCRYPTED), XATTR_CREATE);
    return 0;
}


static int encryptfs_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int encryptfs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int encryptfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
//sets  the extended attribute on the fs

	//adding filepath
	char filepath[1024];
	//filepah = PATH;
	getFullPath(filepath, path);	
	
	//sets x attribute for filepath
	int res = lsetxattr(filepath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int encryptfs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	//adding file path
	char filepath[1024];
	//filepath = PATH;
	getFullPath(filepath, path);
	
	//gets the x a
	int res = lgetxattr(filepath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encryptfs_listxattr(const char *path, char *list, size_t size)
{	
	char filepath[1024];
//	strcpy(filePath, PATH);
//	strncat(filePath, path, MAX_SIZE);
	getFullPath(filepath, path);	
	
	//retrieve list of extended attirbutes, in case of symbolic link get the attr associated with link itself
	int res = llistxattr(filepath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encryptfs_removexattr(const char *path, const char *name)
{
	char filepath[1024];
//	strcpy(filePath, PATH);
//	strncat(filePath, path, 1024);
	getFullPath(filepath, path);

	int res = lremovexattr(filepath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */
//change all operations to encryptfs functions
static struct fuse_operations encryptfs_oper = {
	.getattr	= encryptfs_getattr,
	.access		= encryptfs_access,
	.readlink	= encryptfs_readlink,
	.readdir	= encryptfs_readdir,
	.mknod		= encryptfs_mknod,
	.mkdir		= encryptfs_mkdir,
	.symlink	= encryptfs_symlink,
	.unlink		= encryptfs_unlink,
	.rmdir		= encryptfs_rmdir,
	.rename		= encryptfs_rename,
	.link		= encryptfs_link,
	.chmod		= encryptfs_chmod,
	.chown		= encryptfs_chown,
	.truncate	= encryptfs_truncate,
	.utimens	= encryptfs_utimens,
	.open		= encryptfs_open,
	.read		= encryptfs_read,
	.write		= encryptfs_write,
	.statfs		= encryptfs_statfs,
	.create         = encryptfs_create,
	.release	= encryptfs_release,
	.fsync		= encryptfs_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= encryptfs_setxattr,
	.getxattr	= encryptfs_getxattr,
	.listxattr	= encryptfs_listxattr,
	.removexattr	= encryptfs_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	//args: key, target path, mount point
	//char cwd[1024];
//need data typ eot pass fuse_main
	
	//adding code for specificatin of file system
	printf("In main: adding path via realpath\n");
	//PATH = getcwd(cwd,sizeof(cwd));
	//*PATH = realpath(argv[2], NULL);
	//add encryption key phrase
	//*KEYPHRASE = argv[1];
	encryptfs_vars private_data;
	private_data.rootPath = realpath(argv[2], NULL);
	private_data.keyPhrase = argv[1];

	umask(0);
	//now ready: call with args, operations, and private data
	return fuse_main(argc-2, argv+2, &encryptfs_oper, &private_data);
}
