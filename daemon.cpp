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
boost::asio::ip::tcp::acceptor acceptor(service);

class talk_to_client;
typedef boost::shared_ptr<talk_to_client> client_ptr;
typedef std::vector<client_ptr> array;
array clients;
boost::recursive_mutex clients_cs;

#define MEM_FN(x)       boost::bind(&self_type::x, shared_from_this())
#define MEM_FN1(x,y)    boost::bind(&self_type::x, shared_from_this(),y)
#define MEM_FN2(x,y,z)  boost::bind(&self_type::x, shared_from_this(),y,z)

std::string crypt_key;						// Ключ для шифрования AES
std::vector<std::string> allowed_ip;		// Список разрешенных IP
int port = 31707;							// Используемый порт

std::map<std::string, std::string> client_keys;		// Список клиенских ключей

bool daemon_stop = false;

void update_clients_changed();

class talk_to_client : public boost::enable_shared_from_this<talk_to_client>
	, boost::noncopyable {
	typedef talk_to_client self_type;
	talk_to_client() : sock_(service), started_(false),
		timer_(service) {
	}
public:
	typedef boost::system::error_code error_code;
	typedef boost::shared_ptr<talk_to_client> ptr;

	void start() {
		{ 
			boost::recursive_mutex::scoped_lock lk(clients_cs);
			clients.push_back(shared_from_this());
		}

		boost::recursive_mutex::scoped_lock lk(cs_);
		started_ = true;

		last_ping_ = boost::posix_time::microsec_clock::local_time();
		// first, we wait for client to login
		do_read();
	}
	static ptr new_() {
		ptr new_(new talk_to_client);
		return new_;
	}
	void stop() {
		{ 
			boost::recursive_mutex::scoped_lock lk(cs_);
			if (!started_) return;
			started_ = false;
			sock_.close();
		}

		ptr self = shared_from_this();
		{ 
			boost::recursive_mutex::scoped_lock lk(clients_cs);
			array::iterator it = std::find(clients.begin(), clients.end(), self);
			clients.erase(it);
		}
	}
	bool started() const {
		boost::recursive_mutex::scoped_lock lk(cs_);
		return started_;
	}
	ip::tcp::socket & sock() {
		boost::recursive_mutex::scoped_lock lk(cs_);
		return sock_;
	}
private:
	void on_read(const error_code & err, size_t bytes) {
		if (err) stop();
		if (!started()) return;

		boost::recursive_mutex::scoped_lock lk(cs_);

		bool found = std::find(read_buffer_, read_buffer_ + bytes, '\n') < read_buffer_ + bytes;

		if (!found)
			return; // message is not full

		client_ip = sock_.remote_endpoint().address().to_string();

		if (!allowed_ip.empty() && !in_array(client_ip, allowed_ip)) {
			std::cout << "Ip not allowed: " << client_ip << std::endl;
			stop();
			return;
		}

		// process the msg
		std::string msg(read_buffer_, bytes);

		if (msg.find("getkey") == 0) get_key();
		else if (msg.find("command ") == 0) on_request(msg);
		else if (msg.find("exit") == 0) close_connect();
		else if (msg.find("quit") == 0) close_connect();
		else if (msg.find("close") == 0) close_connect();
		else std::cerr << "invalid msg " << msg << std::endl;
	}

	void close_connect()
	{
		boost::recursive_mutex::scoped_lock lk(cs_); 
		
		std::cout << "Connection closed " << client_ip << std::endl;
		timeout = 0;
		stop();
		//last_ping_ = boost::posix_time::microsec_clock::local_time();
	}

	void on_request(const std::string & msg)
	{
		if (!started()) return;
		boost::recursive_mutex::scoped_lock lk(cs_);

		if (client_keys[client_ip] == "") {
			std::cout << "Client key not set" << std::endl;

			stop();
			return;
		}

		std::string command;
		boost::regex xRegEx("command (.+)");
		boost::smatch xResults;

		boost::regex_match(msg, xResults, xRegEx);

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
		std::string encoding = jroot.get("encoding", "UTF-8").asString();

		// Check client key
		if (jroot["key"].asString() != client_keys[client_ip]) {
			std::cerr << "The client_key doesn't match" << std::endl;
			std::cerr << "Client_key:" << jroot["key"].asString() << std::endl;
			stop();
			return;
		}

		// Команда может выполняться продолжительное время
		timeout = 1200000;

		try {
			request_processing(jroot, jsend);
		}
		catch (std::exception &e) {
			std::cerr << "Error: " << e.what() << std::endl;
			jsend["status"] = 1;
		}

		timeout = 15000;

		Json::StyledWriter writer;
		write_crypt(writer.write(jsend));

		// Close connection
		//~ stop();
		//~ close = true;
	}

	void get_key()
	{
		if (!started()) return;
		boost::recursive_mutex::scoped_lock lk(cs_); 

		if (client_keys.find(client_ip) != client_keys.end() && client_keys[client_ip] != "") {
			// Key exists
			std::cout << "Key exists: " << client_keys[client_ip] << " " << client_ip << std::endl;
			write_crypt(client_keys[client_ip]);
			return;
		}

		srand(time(NULL));
		auto randchar = []() -> char
		{
			const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
			const size_t max_index = (sizeof(charset)-1);
			return charset[rand() % max_index];
		};

		std::string ckey(16, 0);
		std::generate_n(ckey.begin(), 16, randchar);

		client_keys[client_ip] = ckey;

		write_crypt(ckey);
	}

	void write_crypt(const std::string & msg) {
		std::cout << "Msg size: " << msg.size() << std::endl;
		write(aes_encrypt(msg, crypt_key));
	}

	void write(const std::string & msg) {
		std::cout << "Msg crypt size: " << msg.size() << std::endl;
		do_write(msg);
		do_write("\n");
	}

	void on_write(const error_code & err, size_t bytes) {
		if (!started()) return;
		do_read();
	}
	void do_read() {
		if (!started()) return;
		sock_.async_read_some(boost::asio::buffer(read_buffer_, max_msg), MEM_FN2(on_read, _1, _2));

		boost::posix_time::ptime now = boost::posix_time::microsec_clock::local_time();
		if ((now - last_ping_).total_milliseconds() > timeout) {
			std::cout << "Stopping. No ping in time" << std::endl;
			stop();
		}
	}
	void do_write(const std::string & msg) {
		if (!started()) return;
		boost::recursive_mutex::scoped_lock lk(cs_);
		if (!started()) return;
		//~ std::copy(msg.begin(), msg.end(), write_buffer_);
		sock_.async_write_some(buffer(msg),
			MEM_FN2(on_write, _1, _2));
	}
private:
	mutable boost::recursive_mutex cs_;
	ip::tcp::socket sock_;
	enum { max_msg = 2000000 }; // 2 Mb
	char read_buffer_[max_msg];
	//~ char write_buffer_[max_msg];
	bool started_;
	deadline_timer timer_;
	boost::posix_time::ptime last_ping_;

	std::string client_ip;
	std::string client_key;

	int timeout = 15000;
};

void handle_accept(talk_to_client::ptr client, const boost::system::error_code & err)
{
	client->start();
	talk_to_client::ptr new_client = talk_to_client::new_();
	acceptor.async_accept(new_client->sock(), boost::bind(handle_accept, new_client, _1));
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
	}
	catch (std::exception &e) {
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
		crypt_key = crypt_key + std::string(16 - crypt_key.size(), '*');
	}
	else if (crypt_key.size() > 16) {
		crypt_key = crypt_key.substr(0, 16);
	}
}

void stop_daemon()
{
	//daemon_stop = true;
}

boost::thread_group threads;

void listen_thread() {
	service.run();
}

void start_listen(int thread_count) {
	for (int i = 0; i < thread_count; ++i)
		threads.create_thread(listen_thread);
}

void run_daemon()
{
	if (crypt_key.size() != 16) {
		fix_crypt_key();
	}

	try {
		boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), port);
		acceptor.open(endpoint.protocol());
		acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
		acceptor.bind(endpoint);
		acceptor.listen();

		std::cout << "Server started on port " << port << std::endl;

		talk_to_client::ptr client = talk_to_client::new_();
		acceptor.async_accept(client->sock(), boost::bind(handle_accept, client, _1));

		start_listen(5);
		threads.join_all();

		//~ service.run();
	}
	catch (std::exception &e) {
		std::cerr << "Server error: " << e.what() << std::endl;
	}

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

	switch (pid) {
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
