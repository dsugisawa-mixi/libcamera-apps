/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020, Raspberry Pi (Trading) Ltd.
 *
 * net_output.cpp - send output over network.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include "net_output.hpp"

NetOutput::NetOutput(VideoOptions const *options) : Output(options)
{
	char protocol[4];
	int start, end, a, b, c, d, port;
	if (sscanf(options->output.c_str(), "%3s://%n%d.%d.%d.%d%n:%d", protocol, &start, &a, &b, &c, &d, &end, &port) != 6)
		throw std::runtime_error("bad network address " + options->output);
	std::string address = options->output.substr(start, end - start);

	if (strcmp(protocol, "udp") == 0)
	{
		saddr_ = {};
		saddr_.sin_family = AF_INET;
		saddr_.sin_port = htons(port);
		if (inet_aton(address.c_str(), &saddr_.sin_addr) == 0)
			throw std::runtime_error("inet_aton failed for " + address);

		fd_ = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd_ < 0)
			throw std::runtime_error("unable to open udp socket");
		if (options->verbose)
			std::cerr << "Connecting to udp - server..." << std::endl;
		if (connect(fd_, (struct sockaddr *)&saddr_, sizeof(sockaddr_in)) < 0)
			throw std::runtime_error("connect to udp - server failed");
		if (options->verbose)
			std::cerr << "Connected" << std::endl;
		saddr_ptr_ = (const sockaddr *)&saddr_; // sendto needs these for udp
		sockaddr_in_size_ = sizeof(sockaddr_in);
	}
	else if (strcmp(protocol, "tcp") == 0)
	{
		// WARNING: I've not actually tried this yet...
		if (options->listen)
		{
			// We are the server.
			int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
			if (listen_fd < 0)
				throw std::runtime_error("unable to open listen socket");

			sockaddr_in server_saddr = {};
			server_saddr.sin_family = AF_INET;
			server_saddr.sin_addr.s_addr = INADDR_ANY;
			server_saddr.sin_port = htons(port);

			int enable = 1;
			if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
				throw std::runtime_error("failed to setsockopt listen socket");

			if (bind(listen_fd, (struct sockaddr *)&server_saddr, sizeof(server_saddr)) < 0)
				throw std::runtime_error("failed to bind listen socket");
			listen(listen_fd, 1);

			if (options->verbose)
				std::cerr << "Waiting for client to connect..." << std::endl;
			fd_ = accept(listen_fd, (struct sockaddr *)&saddr_, &sockaddr_in_size_);
			if (fd_ < 0)
				throw std::runtime_error("accept socket failed");
			if (options->verbose)
				std::cerr << "Client connection accepted" << std::endl;

			close(listen_fd);
		}
		else
		{
			// We are a client.
			saddr_ = {};
			saddr_.sin_family = AF_INET;
			saddr_.sin_port = htons(port);
			if (inet_aton(address.c_str(), &saddr_.sin_addr) == 0)
				throw std::runtime_error("inet_aton failed for " + address);

			fd_ = socket(AF_INET, SOCK_STREAM, 0);
			if (fd_ < 0)
				throw std::runtime_error("unable to open client socket");

			if (options->verbose)
				std::cerr << "Connecting to server..." << std::endl;
			if (connect(fd_, (struct sockaddr *)&saddr_, sizeof(sockaddr_in)) < 0)
				throw std::runtime_error("connect to server failed");
			if (options->verbose)
				std::cerr << "Connected" << std::endl;
		}

		saddr_ptr_ = NULL; // sendto doesn't want these for tcp
		sockaddr_in_size_ = 0;
	}
	else
		throw std::runtime_error("unrecognised network protocol " + options->output);
	mtu_buffer_.resize(MTU_SIZE + HEADER_SIZE);
}

NetOutput::~NetOutput()
{
	close(fd_);
}

#ifndef MIN
#define MIN(a,b) (a<b?a:b)
#endif

int NetOutput::sendAll(int fd, void* data, int len)
{
	int	ret = 0L;
	int allsend = 0L;
	int sendlen = 0L;
	int errored = 0;
	int retrycnt = 0L;
	char* senddata = (char*)data;
	fd_set sendfd;
	struct timeval timeout;
	//
	while(1) {
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;
		FD_ZERO(&sendfd);
		FD_SET(fd, &sendfd);
		ret = select(fd + 1, NULL, &sendfd, NULL, &timeout);
		//retry count is over.
		if (retrycnt ++ > 10) {
			errored = 1;
			break;
		}
		if (ret == -1) {
			if (errno == EINTR){ continue; }
			errored = 1;
			break;
		} else if(ret > 0) {
			if(FD_ISSET(fd, &sendfd)) {
				sendlen = send(fd, (senddata + allsend), (len - allsend), 0);
				if (sendlen < 0) {
					errored = 1;
					break;
				}
				allsend += sendlen;
				if (allsend >= len){ break; }
			}
		} else {
			continue;
		}
	}
	return(errored == 0?allsend:-1);
}

void NetOutput::outputBuffer(void *mem, size_t size, int64_t /*timestamp_us*/, uint32_t /*flags*/)
{
	if (options_->verbose)
		std::cerr << "NetOutput: output buffer " << mem << " size " << size << "\n";
	static unsigned seqnumber = 0;
	const unsigned PKTSIZE = MTU_SIZE;
	unsigned bytes_written = 0;
	unsigned header[4] = {0};
	int splitted = (int)(size / PKTSIZE) + ((size % PKTSIZE)==0?0:1);
	//
	for(int n = 0; n < splitted; n++) {
		seqnumber ++;
		int trgtlen = MIN(PKTSIZE, size - bytes_written);
		if ((n+1) == splitted) {
			header[2] = htonl(1<<31 | seqnumber);
		} else {
			header[2] = htonl(seqnumber);
		}
		header[0] = htonl(0xdeadbeaf);
		header[1] = htonl(((int)(getenv("PLAYERIDX")==NULL?1:atoi(getenv("PLAYERIDX")))));
		header[3] = htonl(trgtlen);
		memcpy(mtu_buffer_.data(), header, sizeof(header));
		memcpy(mtu_buffer_.data() + sizeof(header), (char*)mem + bytes_written, trgtlen);

		auto sended = sendAll(fd_, mtu_buffer_.data(), trgtlen + sizeof(header));
		if (sended < 0)
			throw std::runtime_error("failed to send data on socket");
		if (sended != (int)(trgtlen + sizeof(header))) {
			printf("could not sendto\n");
			break;
		}
		bytes_written += trgtlen;
	}
}
