#include <string>
#include <vector>

#ifndef FUNCTIONS_H
#define FUNCTIONS_H

// ---------------------------------------------------------------------

int substr_count(std::string source, std::string substring);

// ---------------------------------------------------------------------

std::string str_replace(const std::string& search,
                        const std::string& replace,
                        const std::string& subject);

// ---------------------------------------------------------------------

std::string trim(std::string& str);

// ---------------------------------------------------------------------

void fast_exec(std::string command);

// ---------------------------------------------------------------------

std::string exec(std::string command);

// ---------------------------------------------------------------------

std::vector<std::string> explode(std::string delimiter, std::string inputstring);

// ---------------------------------------------------------------------

std::string implode(std::string delimiter, std::vector<std::string> & elements);

// ---------------------------------------------------------------------

int get_cores_count();

// ---------------------------------------------------------------------

bool in_array(const std::string &needle, const std::vector< std::string > &haystack);

#endif
