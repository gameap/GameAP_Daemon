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

#include "crypt.h"

#include <jsoncpp/json/json.h>

#include "functions.h" 

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

std::map<std::string,std::string> client_keys;				// Список клиенских ключей

bool stop = false;

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
        return ms > 5000 ;
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
            
        if (!allowed_ip.empty() && !in_array(client_ip, allowed_ip)) {
			std::cout << "Ip not allowed: " << client_ip << std::endl;
			stop();
			return;
		}
		
		//~ std::cout << "Request from " << client_ip << std::endl;
            
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

		if (jroot["type"].asString() == "commands") {
			// Send commands
			
			int jsize = jroot["commands"].size();
			std::vector<std::string> command_results(jsize);
			
			for (int i = 0; i < jsize; i++) {
				command_results[i] = exec(jroot["commands"][i].asString());
				std::cout << "Command exec: " 	<< jroot["commands"][i].asString() << std::endl;
				std::cout << "Result: " 		<< command_results[i] << std::endl;
				
				jsend["command_results"][i] = command_results[i];
			}
			jsend["status"] = 20;
		}
		else if (jroot["type"].asString() == "install") {
			// Install game server
			jsend["status"] = 20;
		}
		else {
			// Unknown type
			jsend["status"] = 31;
		}
		
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
        write(aes_encrypt(msg, crypt_key));
    }

    void write(const std::string & msg) {
        sock_.write_some(buffer(msg));
        sock_.write_some(buffer("\n"));
    }
    
private:
    ip::tcp::socket sock_;
    enum { max_msg = 4096 };
    int already_read_;
    char buff_[max_msg];
    bool started_;
    ptime last_ping;
    std::string client_ip;
    std::string client_key;
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
    }
}

/**
 * Парсер конфигурации
 */
void parse_config()
{
	boost::property_tree::ptree pt;
	std::string allowed_ip_str;

	try {
		boost::property_tree::ini_parser::read_ini("server.cfg", pt);
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

void stop_daemon()
{
	stop = true;
}

void run_daemon()
{
	boost::thread_group threads;
	threads.create_thread(accept_thread);
	threads.create_thread(handle_clients_thread);
	threads.join_all();
}

int main(int argc, char* argv[]) 
{
    parse_config();

#ifdef WIN32
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
	run_daemon();
#endif
}
