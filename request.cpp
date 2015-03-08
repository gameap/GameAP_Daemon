#include <iostream>

#include <jsoncpp/json/json.h>

#include "functions/functions.h" 
#include "functions/files.h"

#include "crypt.h"

// ---------------------------------------------------------------------

/**
 * Возвращает true в случае успеха, либо false в случае ошибки.
 */
bool request_processing(Json::Value & jroot, Json::Value & jsend)
{
	if (jroot["type"].asString() == "commands") {
		// Send commands

		std::string sendcmd;
		int jsize = jroot["commands"].size();
		std::vector<std::string> command_results(jsize);
		
		for (int i = 0; i < jsize; i++) {
			sendcmd = jroot["commands"][i].asString();

			// Replace 
			#ifdef WIN32
				sendcmd = str_replace("%PROGRAMFILES%", "C:\\Programm Files", sendcmd);
				sendcmd = str_replace("%WINDIR%", "C:\\Windows", sendcmd);
			#endif

			command_results[i] = exec(sendcmd);
			std::cout << "Command exec: " 	<< jroot["commands"][i].asString() << std::endl;
			std::cout << "Result: " 		<< command_results[i] << std::endl;
			std::cout << "Result size: " << command_results[i].size() << std::endl;
			
			jsend["command_results"][i] = command_results[i];
		}
		jsend["status"] = 10;
		
		sendcmd.clear();
	}
	else if (jroot["type"].asString() == "read_dir") {
		
		// Read directory
		std::vector<std::string> files;

		if (getdir(jroot["dir"].asString(), files) == -1) {
			// Read failed
			jsend["status"] = 31;
			return 0;
		} 
		
		for (unsigned int i = 2; i < files.size();i++) {
			// File name
			jsend["list"][i-2][0] = files[i];
			
			// File mtime
			jsend["list"][i-2][1] = filemtime(jroot["dir"].asString() + '/' + files[i]);
			
			// File size
			jsend["list"][i-2][2] = filesize(jroot["dir"].asString() + '/' + files[i]);
			
			// Is dir?
			jsend["list"][i-2][3] = is_dir(jroot["dir"].asString() + '/' + files[i]);
		}
			
		jsend["status"] = 10;

	}
	else if (jroot["type"].asString() == "read_file") {
		// Read file
		
		if (!file_exists(jroot["file"].asString())) {
			jsend["status"] = 41;
			return 0;
		}
		
		// 2Mb
		if (filesize(jroot["file"].asString()) > 2000000) {
			// File big
			jsend["status"] = 42;
			return 0;
		}
		
		jsend["contents"] 	= base64_encode(file_get_contents(jroot["file"].asString()));
		jsend["filesize"] 	= std::to_string(jsend["contents"].asString().size());
		jsend["status"] 	= 10;
	}
	else if (jroot["type"].asString() == "write_file") {
		// Write file
		if (file_put_contents(jroot["file"].asString(), base64_decode(jroot["contents"].asString()))) {
			jsend["status"] = 10;
		} 
		else {
			jsend["status"] = 51;
		}
	}
	else if (jroot["type"].asString() == "mkdir") {
		if (make_dir(jroot["dir"].asString(), jroot["permissions"].asString())) {
			jsend["status"] = 10;
		}
		else {
			// Error make
			jsend["status"] = 61;
		}
	}
	else if (jroot["type"].asString() == "move") {
		if (!file_exists(jroot["old_file"].asString())) {
			jsend["status"] = 72;
			return 0;
		}
		
		if (!rename(jroot["old_file"].asString().c_str(), jroot["new_file"].asString().c_str())) {
			// Success
			jsend["status"] = 10;
		}
		else {
			jsend["status"] = 71;
		}
	}
	else if (jroot["type"].asString() == "file_size") {
		// File size
		jsend["filesize"] = filesize(jroot["file"].asString());
	}
	else if (jroot["type"].asString() == "install") {
		// Install game server
		jsend["status"] = 10;
	}
	else if (jroot["type"].asString() == "get_stats") {
		// Get CPU and RAM stats
		jsend["status"] = 10;
	}
	else {
		// Unknown type
		jsend["status"] = 1;
	}
	
	return 1;
}
