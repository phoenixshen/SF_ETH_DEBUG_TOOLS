// udp_server.cpp : irom eth download
//

#include "stdafx.h"
#include "stdio.h"
#include "string.h"
#include "winsock2.h"
#include "windows.h"
#include "download.h"
#include <sys/timeb.h>
#include <iostream>
#pragma comment(lib,"ws2_32.lib")
static SOCKET serSocket = 0;
static int noblock = 1;
extern u32 crc32( u8 *buf, u32 len);
static unsigned int __debug_mode = DEBUG_LVL_SLIENCE;
//static int __debug_mode = DEBUG_LVL_DEBUG;
static unsigned int ret_value = 0;
char memory_path[400] = { 0 };
static unsigned int last_address = 0;
static unsigned int end_address = 0;

enum cmd_type_e {
	TYPE_READ_REG = 1,
	TYPE_WRITE_REG,
	TYPE_READ_MEM,
	TYPE_WRITE_MEM,
	TYPE_PHY_INIT,
	TYPE_IQ_PLAYER_START,
	TYPE_IQ_PLAYER_STOP,
	TYPE_IQ_RECORD_START,
	TYPE_IQ_RECORD_STOP,
	TYPE_UPDATE,
};

struct cmd_args_t{
    enum cmd_type_e cmd_type;
    unsigned long address;
    long value;
    u16 len;
    char print_out;
    char reboot;
    char width;
	char hw_sel;
	char band_sel;
	char band_width;
	char continuous;
	unsigned int iq_count;
}g_cmd_args;

#define ENABLE_CONSOLE_COLOR 1
#define PADDING_SIZE 4
/*
    irom_packet_header
	data[]
	u32 crc
*/
#pragma pack(1)
struct irom_packet_header{
	u16 padding; // padding for board firmware parse data 
	char identify[4];
	u16 packet_len;
	u16 cmd;
	u32 address;
	u32 value;
	u32 width;
};

struct irom_packet_header_write_mem {
	u16 padding; // padding for board firmware parse data 
	char identify[4];
	u16 packet_len;
	u16 cmd;
	u32 address;
};
struct irom_packet_header_rx{
	char identify[4];
	u16 packet_len;
	u16 cmd;
	u32 value;
	u32 address;
};

static char DL_INDENTIFY[4] = {(char)0xaa,(char)0x44,(char)0xbb,(char)0xdd}; //0xaa44bbdd

enum server_state {
	STATE_WAIT_CONNECT,
	STATE_WAIT_READY,
	STATE_WAIT_ADDRESS_ACK,
	STATE_WAIT_FILE_START,
	STATE_WAIT_IMAGE_ACK,
	STATE_WAIT_CHECKSUM_ACK,
	STATE_WAIT_FINISH_ACK,
	STATE_NOT_BROADCAST,
};

static server_state f_state = STATE_WAIT_CONNECT;
static sockaddr connect_server_addr;
static struct file_transfer_context{
	FILE *fd;
	int offset;
	int size;
	int seq_no;
	int complete;
	int starttime;
	int address;
	u8 checksum;
	int index;
}f_file_context; 

#define TEST_COLOR_INDEX_BLUE 9
#define TEST_COLOR_INDEX_GREEN 10
#define TEST_COLOR_INDEX_RED 12
#define TEST_COLOR_INDEX_WHITE 15


void set_console_color(unsigned short color_index)
{
	if(ENABLE_CONSOLE_COLOR) SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color_index);
}

void restore_console_color()
{
	set_console_color(TEST_COLOR_INDEX_WHITE);
}

#define PRINT_ERR(format,...) \
	set_console_color(TEST_COLOR_INDEX_RED); \
	printf(format,##__VA_ARGS__); \
	restore_console_color();

static void fill_crc(u8 *buffer,u32 buffer_len)
{
	//set crc, calc CRC should not count the  padding_end 
	int *crc = (int*)(buffer + buffer_len - 4);
	*crc = htonl(crc32(buffer + 2, (buffer_len - 4 - 2)));
}

int eth_send_memory(int socket,struct sockaddr *remoteAddr,int addr_len){
	if(f_file_context.fd == NULL){
		 printf("file handle is NULL \n");
		return -1;
	}
	if (f_file_context.address + f_file_context.offset == last_address) {
		 printf(" send the same address twice %08x \n", last_address);
		return -1;
	}
	else {
		last_address = f_file_context.address + f_file_context.offset;
	}

	fseek(f_file_context.fd,f_file_context.offset,SEEK_SET);
	char packet[1024];
	int bytes = fread(packet,1,sizeof(packet),f_file_context.fd);
	printf("read file  %d offset %d size %d\n",bytes,f_file_context.offset,f_file_context.size);
	if((f_file_context.offset + bytes) >= f_file_context.size){
		fseek(f_file_context.fd,f_file_context.offset,SEEK_SET);
		bytes = fread(packet,1,f_file_context.size - f_file_context.offset,f_file_context.fd);
		f_file_context.complete = 1;
		end_address = last_address;
	}
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("start send %d\n",bytes);
	if(bytes > 0){
		//send image(with 4 byte crc)
		int buffer_len = sizeof(struct irom_packet_header_write_mem) + bytes + 4;
		u8 *buffer = (u8 *)malloc(buffer_len);
		if (buffer == NULL) {
			return -1;
		}

		struct irom_packet_header_write_mem*  ptx_hdr = (struct irom_packet_header_write_mem*)buffer;
		memcpy(ptx_hdr->identify, DL_INDENTIFY, sizeof(DL_INDENTIFY));
		ptx_hdr->cmd = htons(FUNC_MEM_W);
		ptx_hdr->packet_len = htons((u16)(sizeof(struct irom_packet_header_write_mem) + bytes - sizeof(ptx_hdr->padding)));
		ptx_hdr->address = htonl(f_file_context.address + f_file_context.offset);

		memcpy(buffer + sizeof(struct irom_packet_header_write_mem),packet,bytes);
		//set header
		//set crc
		fill_crc(buffer,buffer_len);
		//send packet
		sendto(socket, (char *)buffer, buffer_len , 0, remoteAddr, addr_len);
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("send packet write address 0x%x size %d\n",f_file_context.address + f_file_context.offset,bytes);
		free(buffer);
		f_file_context.offset += bytes;
	}
	return bytes;
}

int eth_recv_memory(char * buf,int len){
	if(f_file_context.fd == NULL){
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("file handle is NULL \n");
		return -1;
	}
	fseek(f_file_context.fd,f_file_context.offset,SEEK_SET);
	fwrite(buf,1,len,f_file_context.fd);
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf(" offset %d len %d size %d\n",f_file_context.offset, len, f_file_context.size);
	if((f_file_context.offset + len) == f_file_context.size){
		f_file_context.complete = 1;
	}
	f_file_context.offset += len;
	return len;
}

static int eth_send_message(u16 cmd, int address, int socket, struct sockaddr *remoteAddr, int addr_len, int value, int width)
{
	// 4 vytes is for CRC32
	int buffer_len = sizeof(struct irom_packet_header) + 4;
	u8 *buffer = (u8 *)malloc(buffer_len);
	if (buffer == NULL)
		return -1;
	struct irom_packet_header*  ptx_hdr = (struct irom_packet_header*)buffer;
	memcpy(ptx_hdr->identify, DL_INDENTIFY, sizeof(DL_INDENTIFY));
	ptx_hdr->cmd = htons(cmd);
	ptx_hdr->packet_len = htons(sizeof(irom_packet_header) - sizeof(ptx_hdr->padding));
	ptx_hdr->address = htonl(address);
	ptx_hdr->value = htonl(value);
	ptx_hdr->width = htonl(width);
	fill_crc(buffer, buffer_len);
	//send packet
	sendto(socket, (char *)buffer, buffer_len, 0, remoteAddr, addr_len);
	free(buffer);
	if (__debug_mode > DEBUG_LVL_SLIENCE) printf("send: cmd=%x\n", (int)cmd);
	return 0;
}

int send_cmd(SOCKET socket1)
{
	bool bOpt = true;
	SOCKADDR_IN saUdpServ;
	memset(&saUdpServ, 0, sizeof(saUdpServ));
	saUdpServ.sin_family = AF_INET;
	saUdpServ.sin_addr.S_un.S_addr = htonl(INADDR_BROADCAST);
	saUdpServ.sin_port = htons(7001);	
	int nSize = sizeof(SOCKADDR_IN);	
	int len = 0;

	setsockopt(socket1, SOL_SOCKET, SO_BROADCAST, (char*)&bOpt, sizeof(bOpt));

	switch (g_cmd_args.cmd_type) {
	case TYPE_READ_REG:
		eth_send_message(FUNC_REG_R, g_cmd_args.address, socket1, (struct sockaddr *)&saUdpServ, nSize, 0, g_cmd_args.width);
		return 1;

	case TYPE_PHY_INIT:
		eth_send_message(FUNC_PHY_INIT, g_cmd_args.address, socket1, (struct sockaddr *)&saUdpServ, nSize, 0, 0);
		return 1;

	case TYPE_WRITE_REG:
		eth_send_message(FUNC_REG_W, g_cmd_args.address, socket1, (struct sockaddr *)&saUdpServ, nSize, g_cmd_args.value, g_cmd_args.width);
		return 1;
	case TYPE_READ_MEM:
		if (g_cmd_args.len - 1024 < 0)
			len = g_cmd_args.len;
		else
			len = 1024;

		if (len > 0) {
			eth_send_message(FUNC_MEM_R, g_cmd_args.address, socket1, (struct sockaddr *)&saUdpServ, nSize, len, 0);
			g_cmd_args.len -= len;
			g_cmd_args.address += len;
		}
		else {
			return 1;
		}

		break;
	case TYPE_WRITE_MEM:
		if (!f_file_context.complete)
			eth_send_memory(socket1, (struct sockaddr *)&saUdpServ, nSize);
		else
			return 1;
		break;

	case TYPE_IQ_PLAYER_START:
		g_cmd_args.address = g_cmd_args.hw_sel + (g_cmd_args.band_sel << 8) + (g_cmd_args.band_width << 16) + (g_cmd_args.continuous << 24);
		eth_send_message(FUNC_IQ_PLAYER_START, g_cmd_args.address, socket1, (struct sockaddr *)&saUdpServ, nSize, g_cmd_args.iq_count, 0);
		return 1;

	case TYPE_IQ_PLAYER_STOP:
		eth_send_message(FUNC_IQ_PLAYER_STOP, 0, socket1, (struct sockaddr *)&saUdpServ, nSize, 0, 0);
		return 1;

	case TYPE_IQ_RECORD_START:
		g_cmd_args.address = g_cmd_args.hw_sel + (g_cmd_args.band_sel << 8) + (g_cmd_args.band_width << 16) + (g_cmd_args.continuous << 24);
		eth_send_message(FUNC_IQ_RECORD_START, g_cmd_args.address, socket1, (struct sockaddr *)&saUdpServ, nSize, g_cmd_args.iq_count, 0);
		return 1;

	case TYPE_IQ_RECORD_STOP:
		eth_send_message(FUNC_IQ_RECORD_STOP, 0, socket1, (struct sockaddr *)&saUdpServ, nSize, 0, 0);
		return 1;


	default:
		if (g_cmd_args.reboot == 1)
			eth_send_message(FUNC_REBOOT, 0, socket1, (struct sockaddr *)&saUdpServ, nSize, 0, 0);
		return 1;
	}
	bOpt = false;
	//set back
	setsockopt(socket1, SOL_SOCKET, SO_BROADCAST, (char*)&bOpt, sizeof(bOpt));
	return 0;
}

//max length 96K
int dump_memory(int address, char* buf, int len) {
	int i = 0;
	for (; i < len; i++) {
		if (i % 16 == 0)
			printf("addr 0x%08x: ", address + i);

		if (i % 4 == 0)
			printf("0x");

		printf("%02x", (unsigned char)*(buf + i));

		if ((i + 1) % 4 == 0)
			printf(" ");

		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
	return 0;
}

int get_response(SOCKET socket,u8 *packet,int pktlen,sockaddr *remoteAddr,int addr_len){
	if(pktlen < sizeof(struct irom_packet_header_rx)) return 0;
	struct irom_packet_header_rx *header = (struct irom_packet_header_rx*)(packet);
	if(memcmp(header->identify,DL_INDENTIFY,sizeof(DL_INDENTIFY))){
		*((u8 *)header->identify + sizeof(header->identify)) = 0;
		printf("unknown packet identify %s\n",(u8 *)header->identify);
		return 0;
	}
	//get cmd
	u16 cmd = htons(header->cmd) & 0xFF;
	u8 err = (u8)((htons(header->cmd) & 0xFF00)  >> 8);
	u16 packet_len = htons(header->packet_len);
	u32 value = htonl(header->value);
	u32 address = htonl(header->address);
	switch(cmd) {
		case FUNC_REG_R:
		{
			printf("read value : 0x%08x address 0x%08x\n", value, address);
			ret_value = value;
			return 1;
		}
		case FUNC_PHY_INIT:
		{
			printf("phy init : value %d\n", value);
			ret_value = value;
			return 1;
		}
		case FUNC_REG_W:
		{
			printf("write value : 0x%08x address 0x%08x\n", value, address);
			ret_value = value;
			return 1;
		}
		case FUNC_MEM_R:
		{
			char* read_buf = (char*)packet + 12;
			int read_len = packet_len - 12;
			printf("read address 0x%x  length: %d \n", value, read_len);
			if (g_cmd_args.print_out)
				dump_memory(value, read_buf, read_len);

			eth_recv_memory(read_buf, read_len);
			if (f_file_context.complete == 1)
				return 1;
			return 0;
		}
		break;
		case FUNC_MEM_W:
		{
			printf("write length: %d address %08x\n", value, address);
			if (f_file_context.complete == 1 && end_address == address)
				return 1;
			return 0;
		}
		break;
		case FUNC_IQ_PLAYER_START:
		{
			// 0 = rp init fail 1= already start
			printf("iq_player start iq count %d\n", value);
			return 1;
		}
		break;
		case FUNC_IQ_PLAYER_STOP:
		{
			printf("iq_player stop \n");
			ret_value = value;
			return 1;
		}
		break;
		case FUNC_IQ_RECORD_START:
		{
			// 0 = rp init fail 1= already start
			printf("iq_record start iq count %d\n", value);
			return 1;
		}
		break;
		case FUNC_IQ_RECORD_STOP:
		{
			printf("iq_record stop \n");
			ret_value = value;
			return 1;
		}
		break;
		case FUNC_REBOOT:
		{
			printf("board reboot\n");
			return 1;
		}
		break;

		default:
			break;
	}
	return 0;
}

void getExePath(char *path)
{
	char config_path[256];
	GetModuleFileNameA(NULL,config_path,256);
	int len = strlen(config_path);
	char *tail = &(config_path[len - 1]);
	while(*tail != '\\'){
		tail--;
	}
	*(tail + 1) = 0;
	sprintf_s(path,sizeof(config_path),"%s",config_path);
}


void test_console_color()
{
	int index = 0;
	for(index = 0 ; index < 100 ;index++){
		set_console_color(index);
		printf("fuck color= %d\n",index);
	}
}

static void usage()
{
	std::cout << "Usage: -h will show this" << std::endl;

	std::cout << "-t log level use 2 will print debug log" << std::endl;
	std::cout << "-r read mode input hex address " << std::endl;
	std::cout << "-w write mode input hex address " << std::endl;
	std::cout << "-l input decimal length 16bit should be used with -r or -w if access memory, if not set, will return int value" << std::endl;
	std::cout << "-p if set , do phy init with input decimal" << std::endl;
	std::cout << "-o if set , read memory will print in HEX default is to a file " << std::endl;
	std::cout << "-b if set , reboot after cmd, if no cmd, just reboot" << std::endl;
	std::cout << "-v if set , use with -w, hex value of write reg" << std::endl;
	std::cout << "-i if set , 1 means read/write byte, 2 means word, 3 means int, default is rf read/write" << std::endl;

	// iq_player start params
	std::cout << "-y if set , cmd iq player start " << std::endl;
	std::cout << "-n if set , cmd iq player stop " << std::endl;

	std::cout << "-z if set , cmd iq record start " << std::endl;
	std::cout << "-m if set , cmd iq record stop " << std::endl;

	std::cout << "-s if set , hw select   0 - rf  1 - BB default 0" << std::endl;
	std::cout << "-e if set , band select 0 - low band 1 - high band default 0" << std::endl;
	std::cout << "-d if set , band width  0 - 20Mhz 1 - 40Mhz 2 - 80Mhz default 0" << std::endl;
	std::cout << "-c if set , continuous mode 0 - singe frame 1 - continuous default 0" << std::endl;
	std::cout << "-q if set , IQ count " << std::endl;

	std::cout << "for example:" << std::endl;
	std::cout << "./SF_ETH_DEBUG_TOOLS  -r 0xb0000000 -i1\n" << std::endl;
	std::cout << "./SF_ETH_DEBUG_TOOLS  -w 0xb0000000 -i2 -v0x12" << std::endl;
	std::cout << "./SF_ETH_DEBUG_TOOLS  -r 0xb0000000 -l 2048 -o" << std::endl;
	std::cout << "==read / write memory will use memory.bin==" << std::endl;
	std::cout << "./SF_ETH_DEBUG_TOOLS  -w 0xb0000000 -l 2048 -b" << std::endl;
	std::cout << "/SF_ETH_DEBUG_TOOLS  -z -s 1 -e 1 -d 2 -c 1 -q 1024" << std::endl;

	system("pause");
	exit(0);
}

int parse_args(int argc, char* argv[]){
	if (argc < 2) {
		std::cout << "error args" << std::endl;	
		usage();
		return -1;
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			usage();
			return 0;
		}
		else if(strcmp(argv[i], "-t") == 0){
			__debug_mode = atoi(argv[++i]);
			continue;
		}
		else if (strcmp(argv[i], "-r") == 0) {
			g_cmd_args.cmd_type = TYPE_READ_REG;
			g_cmd_args.address = strtoul(argv[2],NULL,16);
			continue;
		}
		else if (strcmp(argv[i], "-w") == 0) {
			g_cmd_args.cmd_type = TYPE_WRITE_REG;
			g_cmd_args.address = strtoul(argv[++i], NULL, 16);
			continue;
		}
		else if (strcmp(argv[i], "-v") == 0) {
			g_cmd_args.value = strtoul(argv[++i], NULL, 16);
			continue;
		}
		else if (strcmp(argv[i], "-u") == 0) {
			g_cmd_args.cmd_type = TYPE_UPDATE;
			continue;
		}
		else if (strcmp(argv[i], "-b") == 0) {
			g_cmd_args.reboot = 1;
			continue;
		}
		else if (strcmp(argv[i], "-l") == 0) {
			g_cmd_args.len = atoi(argv[++i]);
			continue;
		}
		else if (strcmp(argv[i], "-i") == 0) {
			g_cmd_args.width = atoi(argv[++i]);
			continue;
		}
		else if (strcmp(argv[i], "-o") == 0) {
			g_cmd_args.print_out = 1;
			continue;
		}
		else if (strcmp(argv[i], "-p") == 0) {
			g_cmd_args.cmd_type = TYPE_PHY_INIT;
			g_cmd_args.address = atoi(argv[++i]);
			continue;
		}
		else if (strcmp(argv[i], "-y") == 0) {
			g_cmd_args.cmd_type = TYPE_IQ_PLAYER_START;
			continue;
		}
		else if (strcmp(argv[i], "-n") == 0) {
			g_cmd_args.cmd_type = TYPE_IQ_PLAYER_STOP;
			continue;
		}
		else if (strcmp(argv[i], "-z") == 0) {
			g_cmd_args.cmd_type = TYPE_IQ_RECORD_START;
			continue;
		}
		else if (strcmp(argv[i], "-m") == 0) {
			g_cmd_args.cmd_type = TYPE_IQ_RECORD_STOP;
			continue;
		}
		else if (strcmp(argv[i], "-s") == 0) {
			g_cmd_args.hw_sel = atoi(argv[++i]);
			continue;
		}
		else if (strcmp(argv[i], "-e") == 0) {
			g_cmd_args.band_sel = atoi(argv[++i]);
			continue;
		}
		else if (strcmp(argv[i], "-d") == 0) {
			g_cmd_args.band_width = atoi(argv[++i]);
			continue;
		}
		else if (strcmp(argv[i], "-c") == 0) {
			g_cmd_args.continuous = atoi(argv[++i]);
			continue;
		}
		else if (strcmp(argv[i], "-q") == 0) {
			g_cmd_args.iq_count = atoi(argv[++i]);
			continue;
		}
	}

	if (g_cmd_args.len != 0) {
		if (g_cmd_args.cmd_type == TYPE_READ_REG)
			g_cmd_args.cmd_type = TYPE_READ_MEM;
		else if (g_cmd_args.cmd_type == TYPE_WRITE_REG)
			g_cmd_args.cmd_type = TYPE_WRITE_MEM;
		else {
			std::cout << "error args len set with out write or read" << std::endl;
			return -1;
		}
	} 
	else if (g_cmd_args.cmd_type == TYPE_IQ_PLAYER_START) {
		if (g_cmd_args.iq_count == 0) {
			std::cout << "error args iq start with out iq count" << std::endl;
			return -1;
		}
	}
	return 1;
}

int memory_op_init()
{
	int filesize = 0;
	//close old file if exist
	if (f_file_context.fd != NULL) {
		fclose(f_file_context.fd);
		f_file_context.fd = NULL;
	}
	memset(&f_file_context, 0, sizeof(struct file_transfer_context));
	if (g_cmd_args.cmd_type == TYPE_READ_MEM) {
		if (fopen_s(&f_file_context.fd, memory_path, "wb") != 0) {
			printf("open file memory.bin failed \n");
			return -1;
		}
	}
	else if (g_cmd_args.cmd_type == TYPE_WRITE_MEM) {
		if (fopen_s(&f_file_context.fd, memory_path, "rb") != 0) {
			printf("open file memory.bin failed \n");
			return -1;
		}
	}

	f_file_context.address = g_cmd_args.address;
	if (g_cmd_args.cmd_type == TYPE_READ_MEM) {
		f_file_context.size = g_cmd_args.len;
	}
	else {
		fseek(f_file_context.fd, 0, SEEK_END);
		filesize = ftell(f_file_context.fd);
		if (filesize == 0)
			return -1;
		else if (filesize < g_cmd_args.len) {
			f_file_context.size = filesize;
			if (__debug_mode > DEBUG_LVL_SLIENCE) printf("file is smaller then len. use file size %d\n", filesize);
		}
		else
			f_file_context.size = g_cmd_args.len;
	}

	return 0;

}
int main(int argc, char* argv[])
{
	set_console_color(TEST_COLOR_INDEX_WHITE);
    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2,2);
    if(WSAStartup(sockVersion, &wsaData) != 0)
    {
        return 0;
    }
    for (int i = 0; i < argc; ++i)
    {
		if (__debug_mode > DEBUG_LVL_SLIENCE) printf(" index %d arg %s\n", i, argv[i]);
    	//return 0;
    }
	memset(&g_cmd_args, 0, sizeof(struct cmd_args_t));

	if (parse_args(argc, argv) <= 0)
		return -1;

	if (__debug_mode > DEBUG_LVL_SLIENCE) printf("cmd is %d address is 0x%x  len is %d value is %d\n", g_cmd_args.cmd_type, (int)g_cmd_args.address, g_cmd_args.len, (int)g_cmd_args.value);

	if (g_cmd_args.cmd_type == TYPE_READ_REG || g_cmd_args.cmd_type == TYPE_WRITE_REG) {
		if ((g_cmd_args.address >> 28) == 0 && g_cmd_args.width != 0) {
			printf("address invalid\n");
			return -1;
		}
	}
	char exe_path[256];
	getExePath(exe_path);
	if (__debug_mode > DEBUG_LVL_SLIENCE) printf("module file path = %s\n", exe_path);
	
	memset(&f_file_context,0,sizeof(struct file_transfer_context));

	sprintf_s(memory_path, sizeof(memory_path),"%s/memory.bin", exe_path);
	if (__debug_mode > DEBUG_LVL_SLIENCE) printf("memory_path=%s\n", memory_path);
	if (g_cmd_args.cmd_type == TYPE_WRITE_MEM || g_cmd_args.cmd_type == TYPE_READ_MEM) {
		if (memory_op_init() <0) {
			printf("init memory file failed \n");
			return -1;
		}
	}
    serSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    if(serSocket == INVALID_SOCKET)
    {
        printf("socket error !\n");
        return 0;
    }

    sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
	serAddr.sin_port = htons(6789);
    serAddr.sin_addr.S_un.S_addr = INADDR_ANY;
    if(bind(serSocket, (sockaddr *)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
    {
        printf("bind error !");
        closesocket(serSocket);
        return 0;
    }
	//set read time out
	int timeou_ms = 20;
	setsockopt(serSocket,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeou_ms,sizeof(int));
	if (__debug_mode > DEBUG_LVL_SLIENCE) if (__debug_mode > DEBUG_LVL_SLIENCE) printf("bind start at socket %d!\n", serSocket);

	//set noblock
	ioctlsocket(serSocket,FIONBIO,(u_long FAR*)&noblock);

    sockaddr_in remoteAddr;
    int nAddrLen = sizeof(remoteAddr); 
    //start to receive, if return nothing, send our cmd
    while (true)
    {
        char recvData[2000];  
        int ret = recvfrom(serSocket, recvData, 2000, 0, (sockaddr *)&remoteAddr, &nAddrLen);
        if (ret > 0)
        {
            recvData[ret] = 0x00;
			if (get_response(serSocket, (u8 *)recvData, ret, (sockaddr *)&remoteAddr, nAddrLen) > 0)
				break;
		}
		else {
			if (f_state == STATE_WAIT_CONNECT && f_state != STATE_NOT_BROADCAST) {
				if (send_cmd(serSocket) == 1) {
					f_state = STATE_NOT_BROADCAST;
				}
			}
		}

    }

	if (g_cmd_args.reboot) {
		eth_send_message(FUNC_REBOOT, 0, serSocket, (struct sockaddr *)&remoteAddr, nAddrLen, 0, 0);
		if (__debug_mode > DEBUG_LVL_SLIENCE) printf("send reboot \n");
	}
    closesocket(serSocket); 
    WSACleanup();
	if (__debug_mode > DEBUG_LVL_SLIENCE) printf("return value %08x\n",ret_value);
	//	system("pause");
    return ret_value;
}
