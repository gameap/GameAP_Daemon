#ifdef WIN32
#define _WIN32_WINNT 0x0501
#include <stdio.h>
#endif

#include <sstream>
#include <iostream>
#include <map>

#include <boost/thread.hpp>
#include <boost/regex.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include "functions/functions.h" 
#include "functions/files.h" 
#include "crypt.h"

#include <jsoncpp/json/json.h>

#include "request.h" 

#ifdef WIN32
#include "winservice.h"
#endif

using namespace boost::asio;
using namespace boost::posix_time;
io_service service;

struct talk_to_client;
typedef boost::shared_ptr<talk_to_client> client_ptr;
typedef std::vector<client_ptr> array;
array clients;
// thread-safe access to clients array
boost::recursive_mutex cs;

std::string crypt_key;						// Ключ для шифрования AES
std::vector<std::string> allowed_ip;		// Список разрешенных IP
int port = 31707;							// Используемый порт

std::map<std::string,std::string> client_keys;		// Список клиенских ключей

bool daemon_stop = false;

struct talk_to_client : boost::enable_shared_from_this<talk_to_client> {
    talk_to_client() 
        : sock_(service), started_(false), already_read_(0) {
        last_ping = microsec_clock::local_time();
    }
    
    void answer_to_client() 
    {
        try {
            read_request();
            process_request();
        } catch ( boost::system::system_error&) {
            stop();
        }
        
        if ( timed_out()) {
            stop();
            std::cout << "Stopping. No ping in time" << std::endl;
        }
    }
	
    ip::tcp::socket & sock() { return sock_; }
    
	bool timed_out() const
    {
        ptime now = microsec_clock::local_time();
        long long ms = (now - last_ping).total_milliseconds();

		/*
		Если выполняется команда, то timeout не учитывается,
		т.к. команды могут выполняться продолжительное время.

		Команда должна выполняться не более 20 минут.
		*/
		if (wait && ms < 1200000) {
			return false;
		}

		// Остановка демона
		if (daemon_stop) {
			return true;
		}

        return ms > 60000 ;
    }
    
    void stop() 
    {
		//~ client_keys.erase(client_ip);
        
        // close client connection
        boost::system::error_code err;
        sock_.close(err);
    }
private:
    void read_request() 
    {
        if ( sock_.available())
            already_read_ += sock_.read_some(
                buffer(buff_ + already_read_, max_msg - already_read_));
    }
    
    void process_request() 
    {
        bool found_enter = std::find(buff_, buff_ + already_read_, '\n') < buff_ + already_read_;
                          
        if ( !found_enter)
            return; // message is not full
            
        client_ip = sock_.remote_endpoint().address().to_string();
		wait = false;
            
        if (!allowed_ip.empty() && !in_array(client_ip, allowed_ip)) {
			std::cout << "Ip not allowed: " << client_ip << std::endl;
			stop();
			return;
		}
		
		// std::cout << "Request from " << client_ip << std::endl;
            
        // process the msg
        last_ping = microsec_clock::local_time();
        size_t pos = std::find(buff_, buff_ + already_read_, '\n') - buff_;
        std::string msg(buff_, pos);
        std::copy(buff_ + already_read_, buff_ + max_msg, buff_);
        already_read_ -= pos + 1;
        
        if ( msg.find("getkey") == 0) get_key();
        else if ( msg.find("command ") == 0) on_request(msg);
        else if ( msg.find("exit") == 0) stop();
        else if ( msg.find("quit") == 0) stop();
        else std::cerr << "invalid msg " << msg << std::endl;
    }
    
    void on_request(const std::string & msg) 
    {
		if (client_keys[client_ip] == "") {
			std::cout << "Client key not set" << std::endl;

			stop();
			return;
		}
		
		std::string command;
		boost::regex xRegEx("command (.+)");
		boost::smatch xResults;
		
		boost::regex_match(msg,  xResults, xRegEx);
		
		try {
			command = aes_decrypt(xResults[1], crypt_key);
		}
		catch (std::exception &e) {
		   std::cerr << e.what() << std::endl;
		   std::cerr << "String: " << xResults[1] << std::endl;
		}

		Json::Value jroot;	// Read
		Json::Value jsend;  // Write and send
		
		Json::Reader jreader(Json::Features::strictMode());
		jreader.parse(command, jroot, false);
		std::string encoding 	= jroot.get("encoding", "UTF-8" ).asString();
		
		// Check client key
		if (jroot["key"].asString() != client_keys[client_ip]) {
			std::cerr << "The client_key doesn't match" << std::endl;
			std::cerr << "Client_key:" << jroot["key"].asString() << std::endl;
			stop();
			return;
		}
		
		wait = true;
		
		try {
			request_processing(jroot, jsend);
		} catch( std::exception &e ) {
			std::cerr << "Error: " << e.what() << std::endl;
			jsend["status"] = 1;
		}

		wait = false;
		
		Json::StyledWriter writer;
        write_crypt(writer.write( jsend ));
    }
    
    void get_key() {
		
		if ( client_keys.find(client_ip) != client_keys.end() && client_keys[client_ip] != "") {
			// Key exists
			std::cout << "Key exists: " 	<< client_keys[client_ip] << " " << client_ip << std::endl;
			write_crypt(client_keys[client_ip]);
			return;
		}
		
		srand(time( NULL ));
		auto randchar = []() -> char
		{
			const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
			const size_t max_index = (sizeof(charset) - 1);
			return charset[ rand() % max_index ];
		};
		
		std::string ckey(16,0);
		std::generate_n( ckey.begin(), 16, randchar );
		
		client_keys[client_ip] = ckey;

		write_crypt(ckey);
    }
    
	void write_crypt(const std::string & msg) {
		std::cout << "Msg size: " << msg.size() << std::endl;
        write(aes_encrypt(msg, crypt_key));
    }

    void write(const std::string & msg) {
		std::cout << "Msg crypt size: " << msg.size() << std::endl;
        sock_.write_some(buffer(msg));
        sock_.write_some(buffer("\n"));
    }
    
private:
    ip::tcp::socket sock_;
    enum { max_msg = 3145728 }; // 2 Mb + 40%
	int already_read_;
    char buff_[max_msg];
    bool started_;
    ptime last_ping;
    std::string client_ip;
    std::string client_key;
	bool wait = false;
};

void accept_thread() 
{
    try {
		ip::tcp::acceptor acceptor(service, ip::tcp::endpoint(ip::tcp::v4(), port));
		
		std::cout << "Server started on port " << port << std::endl;
		
		while ( true) {
			client_ptr new_( new talk_to_client);
			acceptor.accept(new_->sock());
			
			boost::recursive_mutex::scoped_lock lk(cs);
			clients.push_back(new_);

			if (daemon_stop) {
				break;
			}
		}
		
    } catch( std::exception &e ) {
		std::cerr << "Server error: " << e.what() << std::endl;
		exit(0);
	}
}

void handle_clients_thread() 
{
    while ( true) {
		boost::this_thread::sleep(millisec(100));
        boost::recursive_mutex::scoped_lock lk(cs);
        
        for ( array::iterator b = clients.begin(), e = clients.end(); b != e; ++b) { 
            (*b)->answer_to_client();
		}
            
        // erase clients that timed out
        clients.erase(std::remove_if(clients.begin(), clients.end(), 
                   boost::bind(&talk_to_client::timed_out,_1)), clients.end());

		if (daemon_stop) {
			break;
		}
    }
}
#ifdef WIN32
std::string exe_path() {
	TCHAR tbuffer[_MAX_PATH];
	::GetModuleFileName(NULL, tbuffer, _MAX_PATH);

	std::wstring wbuffer(&tbuffer[0]); //convert to wstring
	std::string path(wbuffer.begin(), wbuffer.end()); //and convert to string.

	std::string::size_type pos = path.find_last_of("\\/");
	return path.substr(0, pos);
}
#endif

/**
 * Парсер конфигурации
 */
void parse_config()
{
	boost::property_tree::ptree pt;
	std::string allowed_ip_str;

	try {
		boost::property_tree::ini_parser::read_ini("daemon.cfg", pt);
		crypt_key = pt.get<std::string>("crypt_key");
		allowed_ip_str = pt.get<std::string>("allowed_ip");
		port = pt.get<int>("server_port");
	} catch( std::exception &e ) {
		std::cerr << "Parse config error: " << e.what() << std::endl;
	}
	
	if (allowed_ip_str != "") {
		allowed_ip = explode(",", allowed_ip_str);
		
		int size = allowed_ip.size();
		for (int i = 0; i < size; i++) {
			allowed_ip[i] = trim(allowed_ip[i]);
		}
	}
}

/**
 * Лог
 */
void dlog()
{
	
}

/**
 * Обрезание, либо добивание ключа шифрования до размера 16 байт
 */
void fix_crypt_key()
{
	if (crypt_key.size() < 16) {
		crypt_key = crypt_key + std::string(16-crypt_key.size(), '*');
	} else if (crypt_key.size() > 16) {
		crypt_key = crypt_key.substr(0, 16);
	}
}

void stop_daemon()
{
	//daemon_stop = true;
}

void run_daemon()
{
	if (crypt_key.size() != 16) {
		fix_crypt_key();
	}

	boost::thread_group threads;
	threads.create_thread(accept_thread);
	threads.create_thread(handle_clients_thread);
	threads.join_all();
}

bool daemon_status() 
{
	if (file_exists("daemon.pid")) {
		return true;
	}
	
	return false;
}

int main(int argc, char* argv[]) 
{
	// Debug
	//parse_config();
	//run_daemon();
	//return 0;

	if (argc >= 2 && (!strcmp(argv[1], "kill") || !strcmp(argv[1], "stop"))) {
		if (!daemon_status()) {
			printf("Failed: daemon not running\n");
			return 0;
		}
		
		std::string pid = file_get_contents("daemon.pid");
		
		#ifdef WIN32
			fast_exec("taskkill /f /pid " + pid);
		#else
			fast_exec("kill " + pid);
		#endif
		
		printf("OK: demon with pid %d is stopped\n", atoi(pid.c_str()));
		
		remove("daemon.pid");
		return 0;
	} 
	#ifdef WIN32
	else if (argc >= 2 && !strcmp(argv[1], "run")) {
		change_dir(exe_path());
		parse_config();
		run_daemon();
		return 0;
	}
	#endif
	
	if (daemon_status()) {
		printf("Failed: daemon is already running\n");
		return 0;
	}
	
	#ifdef WIN32

		/*
		fast_exec("daemon.exe run");
		Sleep(2000);
		
		if (daemon_status()) {
			std::string pid = file_get_contents("daemon.pid");
			printf("OK: demon with pid %d is created\n", pid);
			return 0;
		}
		*/

		change_dir(exe_path());

		// Run Windows service
		SERVICE_TABLE_ENTRY ServiceTable[] =
		{
			{ L"GameAP Daemon", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
			{ NULL, NULL }
		};

		if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
		{
			OutputDebugString(L"GDaemon: Main: StartServiceCtrlDispatcher returned error");
			return GetLastError();
		}
		
	#else
		int pid = fork();
	
		switch(pid) {
			case 0:
				setsid();
			
				fclose(stdin);
				fclose(stdout);
				fclose(stderr);
			
				parse_config();
				run_daemon();
				exit(0);
			case -1:
				printf("Fail: unable to fork\n");
			break;
		
			default:
				file_put_contents("daemon.pid", std::to_string(pid));
				printf("OK: demon with pid %d is created\n", pid);
			break;
		}
	#endif
	
	return 0;
}
