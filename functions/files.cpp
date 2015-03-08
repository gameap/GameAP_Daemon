#include <stdio.h>
#include <iostream>

#include <sstream>
#include <fstream>

#include <algorithm>

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include "files.h"

#ifdef _WIN32

#include <io.h>

typedef int mode_t;

static const mode_t S_ISUID      = 0x08000000;           ///< does nothing
static const mode_t S_ISGID      = 0x04000000;           ///< does nothing
static const mode_t S_ISVTX      = 0x02000000;           ///< does nothing
static const mode_t S_IRUSR      = mode_t(_S_IREAD);     ///< read by user
static const mode_t S_IWUSR      = mode_t(_S_IWRITE);    ///< write by user
static const mode_t S_IXUSR      = 0x00400000;           ///< does nothing

static const mode_t S_IRGRP      = mode_t(_S_IREAD);     ///< read by *USER*
static const mode_t S_IWGRP      = mode_t(_S_IWRITE);    ///< write by *USER*
static const mode_t S_IXGRP      = 0x00080000;           ///< does nothing
static const mode_t S_IROTH      = mode_t(_S_IREAD);     ///< read by *USER*
static const mode_t S_IWOTH      = mode_t(_S_IWRITE);    ///< write by *USER*
static const mode_t S_IXOTH      = 0x00010000;           ///< does nothing
static const mode_t S_IRGRP      = 0x00200000;           ///< does nothing
static const mode_t S_IWGRP      = 0x00100000;           ///< does nothing
static const mode_t S_IXGRP      = 0x00080000;           ///< does nothing
static const mode_t S_IROTH      = 0x00040000;           ///< does nothing
static const mode_t S_IWOTH      = 0x00020000;           ///< does nothing
static const mode_t S_IXOTH      = 0x00010000;           ///< does nothing
#   endif

// ---------------------------------------------------------------------

bool file_exists(std::string file_name) 
{
    std::ifstream f(file_name.c_str());
    
    if (f.good()) {
        f.close();
        return true;
    } else {
        f.close();
        return false;
    }   
}

// ---------------------------------------------------------------------

/**
 * Получение содержимого директории
 */
int getdir (std::string dir, std::vector<std::string> &files)
{
    DIR *dp;
    struct dirent *dirp;

    if ((dp  = opendir(dir.c_str())) == NULL) {
        //~ cout << "Error(" << errno << ") opening " << dir << endl;
        return errno;
    }

    while ((dirp = readdir(dp)) != NULL) {
        files.push_back(std::string(dirp->d_name));
    }

    closedir(dp);
    sort (files.begin(), files.end()); //added from computing.net tip

    return 0;
}

// ---------------------------------------------------------------------

std::string file_get_contents(std::string filename)
{
	std::string line;
	std::string contents = "";
	
	std::ifstream file(filename);
	
	if (file.is_open())
	{
		while (getline(file,line))
		{
			contents = contents + line + "\n";
		}
		
		file.close();
		return contents;
	}

	return "";
}

// ---------------------------------------------------------------------

bool file_put_contents(std::string filename, std::string contents)
{
	std::ofstream file(filename);
	
	std::cout << "FILENAME: " << filename << std::endl;
	std::cout << "CONTENTS: " << contents << std::endl;
	
	if (file.is_open()) {
		file << contents;
		file.close();
		return true;
	} else {
		return false;
	}
}

// ---------------------------------------------------------------------

int filesize(std::string filename)
{
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

// ---------------------------------------------------------------------

int filemtime(std::string filename)
{
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_atime : -1;
}

// ---------------------------------------------------------------------

bool is_dir(std::string filename)
{
    struct stat stat_buf;
    stat( filename.c_str(), &stat_buf );
    return (stat_buf.st_mode & S_IFDIR) != 0;
}

// ---------------------------------------------------------------------

bool make_dir(std::string dir, std::string permissions)
{
	mkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	//~ mode_t mode = strtol(permissions.c_str(), NULL, 8);
	//~ mkdir(dir.c_str(), 000777);
	return is_dir(dir);
}
