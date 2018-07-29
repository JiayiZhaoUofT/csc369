/******************************************************************************

                            Online C Compiler.
                Code, Compile, Run and Debug C program online.
Write your code in this editor and press "Run" button to compile and execute it.

*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <zconf.h>
#include <string.h>
#include <errno.h>
#include "helper.h"

int main(int argc, char **argv) {
    check_argc("Usage: ext2_mkdir <image file name> <absolute path on ext2 disk>\n", argc, 3);
    check_path_format(argv[2]);
    read_disk(argv[1]);
    
    //parsing the target path and get the name of the new directory and the path
    char * target_pathname = NULL;
    char * target_dirname = NULL;
    split_last_part_of_path(argv[2], &target_pathname, &target_dirname);
    
    //check whether the path exists, check whether the directory exists
    struct ext2_inode * tpath_inode;
    struct ext2_inode * find_result;
    tpath_inode = get_inode_by_path(root_inode, target_pathname);
    find_result = find_file(tpath_inode, target_dirname);
    if(tpath_inode == NULL) {// if the path dose not exist return the error message
        return ENOENT;
    }
    if(find_result != NULL && find_result -> i_mode & EXT2_S_IFDIR){// if the directory already exists, return the error message 
        fprintf(stderr, "Directory already exist.\n");
        return EEXIST;
    }
    
    //make the new directory
    //find a new inode
    unsigned int inum = find_free_inode();
    if(inum == 0){// run out of space
        return ENOSPC;
    }
    struct ext2_inode * newdir_inode = NUM_TO_INODE(inum);
    memset(newdir_inode, 0, sb->s_inode_size);
    
    //find a new block
    unsigned int bnum = find_free_block();
    struct block * tblock = (struct block *) BLOCK(bnum);
    
    newdir_inode -> imode = EXT2_S_IFDIR;
    newdir_inode -> i_size = 0;//in bytes???
    
    add_dir_entry_to_block(tpath_inode, inum, EXT2_FT_DIR, target_dirname);
}
