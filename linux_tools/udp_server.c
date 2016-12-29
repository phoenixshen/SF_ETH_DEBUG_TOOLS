//udp_server.cpp : irom eth download
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "download.h"
#include <time.h>
#include <unistd.h>

#define VERSION 0x16122601

#define ETH_PADDING_SIZE_HEADER 2

#define ENABLE_CONSOLE_COLOR 1
static unsigned int last_address = 0;
static unsigned int end_address = 0;

enum cmd_type_e {
	TYPE_READ_REG = 1,
	TYPE_WRITE_REG,
	TYPE_READ_MEM,
	TYPE_WRITE_MEM,
	TYPE_PHY_INIT,
	TYPE_UPDATE,
	TYPE_IQ_PLAYER_START,
	TYPE_IQ_PLAYER_STOP,
	TYPE_IQ_RECORD_START,
	TYPE_IQ_RECORD_STOP,
	TYPE_MEMSET,
	TYPE_LOAD_RF_BIN,
	TYPE_GET_VERSION,
};

struct cmd_args_t{
	enum cmd_type_e cmd_type;
	long address;
	long value;
	int len;
	char print_out;
	char reboot;
	char width;
	char hw_sel;
	char band_sel;
	char band_width;
	char continuous;
	unsigned int iq_count;
}g_cmd_args;

extern u32 crc32( u8 *buf, u32 len);

enum DEBUG_LEVEL{
	DEBUG_LVL_SLIENCE,
	DEBUG_LVL_NORMAL,
	DEBUG_LVL_DEBUG
};

char memory_path[400] = {0};
//print more debug information
static enum DEBUG_LEVEL __debug_mode = DEBUG_LVL_SLIENCE;

/*
   irom_packet_header
   data[]
   u32 crc
   */
#pragma pack(1)
struct irom_packet_header{
	u16 padding;
	char identify[4];
	u16 packet_len;
	u16 cmd;
	u32 seq_no;
};

struct irom_packet_header_rx{
	char identify[4];
	u16 packet_len;
	u16 cmd;
	u32 seq_no;
};

//for file burn address information
#pragma pack(1)
struct irom_packet_addr_info{
	struct irom_packet_header header;
	u32 burn_addr;
	u32 total_len;
	u32 sector_len;
	u32 chip_size;
};

#pragma pack(1)
struct irom_packet_sync{
	struct irom_packet_header header;
	u8 synccode[16];
};

#pragma pack(1)
struct irom_packet_checksum{
	struct irom_packet_header header;
	//now only use checksum[0]
	u8 checksum[4];
};

static char DL_INDENTIFY[4] = {0xaa,0x44,0xbb,0xdd};//0xaa44bbdd

enum server_state{
	STATE_WAIT_CONNECT,
	STATE_WAIT_READY,
	STATE_WAIT_ADDRESS_ACK,
	STATE_WAIT_IMAGE_ACK,
	STATE_WAIT_CHECKSUM_ACK,
	STATE_WAIT_FINISH_ACK,
	STATE_NOT_BROADCAST,
};

struct irom_file_info{
	char path[100];
	//burn address
	unsigned int address;
	int valid;
	int filesize;
	u8 checksum;
};

static struct irom_file_info g_file_list[6];

#define FILE_ARRAY_SIZE sizeof(g_file_list)/sizeof(struct irom_file_info)

static int send_sync_count = 0;
static enum server_state f_state;
static struct sockaddr connect_server_addr;
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
}

void restore_console_color()
{
	set_console_color(TEST_COLOR_INDEX_WHITE);
}

#define PRINT_ERR(format,...) \
	set_console_color(TEST_COLOR_INDEX_RED); \
if(__debug_mode > DEBUG_LVL_SLIENCE) if(__debug_mode > DEBUG_LVL_SLIENCE) printf(format,##__VA_ARGS__); \
restore_console_color();


//check if global arp entry is added
static int g_arp_entry_added = 0;

static void reset_state()
{
	f_state = STATE_WAIT_CONNECT;
	send_sync_count = 0;
	memset(&connect_server_addr,0,sizeof(struct sockaddr));
	if(f_file_context.fd != NULL){
		fclose(f_file_context.fd);
		f_file_context.fd = NULL;
	}
	memset(&f_file_context,0,sizeof(struct file_transfer_context));
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("reset transfer state\n");
}

static void fill_common_header(u8* buffer,u16 cmd,u16 len,u32 seq_no)
{
	struct irom_packet_header *message_pkt = (struct irom_packet_header *)buffer;
	memcpy(message_pkt->identify,DL_INDENTIFY,sizeof(DL_INDENTIFY));
	message_pkt->cmd = htons(cmd);
	message_pkt->packet_len = htons(len - sizeof(message_pkt->padding));
	message_pkt->seq_no = htonl(seq_no);
}

static void fill_crc(u8 *buffer,u32 buffer_len)
{
	int *crc = (int*)(buffer + buffer_len - 4);
	*crc = htonl(crc32(buffer + ETH_PADDING_SIZE_HEADER,buffer_len - 4 - ETH_PADDING_SIZE_HEADER));
}

static void eth_send_message(u16 cmd,int seq_no,int socket,struct sockaddr *remoteAddr,int addr_len, int value, int width)
{
#define PADDING_SIZE 4
	//add extra 4 bytes to avoid padding
	int buffer_len = sizeof(struct irom_packet_header) + 4 + 4 + PADDING_SIZE;
	u8 *buffer = (u8 *)malloc(buffer_len);
	fill_common_header(buffer,cmd,(u16)(sizeof(struct irom_packet_header) +4+ PADDING_SIZE),seq_no);
	int *tmp = (int*)(buffer + buffer_len - 12);
	*tmp = htonl(value);
	tmp = (int*)(buffer + buffer_len - 8);
	*tmp = htonl(width);
	//set crc
	fill_crc(buffer,buffer_len);
	//send packet
	sendto(socket, (char *)buffer, buffer_len, 0, remoteAddr, addr_len);
	free(buffer);
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("send: cmd=%x time[%d]\n",(int)cmd,(int)time(NULL));
}

const u8 SYNC_CODE[] = {
	0x73,0x66,0x61,0x31,0x38,0x2a,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
};

static void eth_send_sync(int socket,struct sockaddr *remoteAddr,int addr_len,int cmd_type, int address)
{
	int buffer_len = sizeof(struct irom_packet_sync) + 4;
	u8 *buffer = (u8 *)malloc(buffer_len);
	fill_common_header(buffer,cmd_type,(u16)(sizeof(struct irom_packet_sync)),address);
	//set sync code
	struct irom_packet_sync *sync = (struct irom_packet_sync *)buffer;
	memcpy(sync->synccode,SYNC_CODE,sizeof(SYNC_CODE));
	//set crc
	fill_crc(buffer,buffer_len);
	sendto(socket, (char *)buffer, buffer_len, 0, remoteAddr, addr_len);
	free(buffer);
	send_sync_count++;
	if(__debug_mode > DEBUG_LVL_SLIENCE)  printf("send SYNCP time[%d] count[%d]%s",(int)time(NULL),send_sync_count,(__debug_mode == DEBUG_LVL_SLIENCE) ? "\033[1A\r\n": "\n");

}

static void eth_send_checksum(int socket,struct sockaddr *remoteAddr,int addr_len)
{
	int buffer_len = sizeof(struct irom_packet_checksum) + 4;
	u8 *buffer = (u8 *)malloc(buffer_len);
	fill_common_header(buffer,FUNC_CHECKSUM,(u16)(sizeof(struct irom_packet_checksum)),0);
	//set checksum
	struct irom_packet_checksum *checksum = (struct irom_packet_checksum *)buffer;
	checksum->checksum[0] = f_file_context.checksum;
	//set crc
	fill_crc(buffer,buffer_len);
	sendto(socket, (char *)buffer, buffer_len, 0, remoteAddr, addr_len);
	free(buffer);
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("send CHECKSUM time[%d]\n",(int)time(NULL));
}

static void eth_send_burn_address(int socket,struct sockaddr *remoteAddr,int addr_len)
{
	int buffer_len = sizeof(struct irom_packet_addr_info) + 4;
	u8 *buffer = (u8 *)malloc(buffer_len);
	fill_common_header(buffer,FUNC_FLASH_START,(u16)(sizeof(struct irom_packet_addr_info)),0);
	//set address
	struct irom_packet_addr_info *addrinfo = (struct irom_packet_addr_info *)buffer;
	addrinfo->burn_addr = htonl(f_file_context.address);
	addrinfo->total_len = htonl(f_file_context.size);
	addrinfo->sector_len = htonl(0x1000);
	addrinfo->chip_size = htonl(0xbc400000);
	//addrinfo->burn_addr = htonl(0xbc000000);
	//addrinfo->total_len = htonl(73728);
	//set crc
	fill_crc(buffer,buffer_len);
	sendto(socket, (char *)buffer, buffer_len, 0, remoteAddr, addr_len);
	free(buffer);
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("send packet address[%x] time[%d]\n",f_file_context.address,(int)time(NULL));
}

#define IMAGE_FILE_ADDRESS 0xbc000000
#define IMAGE_FILE_PATH "E:\\Project\\udp_server\\Debug\\sf1688.bin"

//for byte-4 aligned when handle udp packet data
#define ETH_DATA_PADDING_SIZE 0
static int last_printf_seq_time = 0;
int transfer_image(int socket,struct sockaddr *remoteAddr,int addr_len)
{
	if(f_file_context.fd == NULL){
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("file handle is NULL \n");
		return -1;
	}
	fseek(f_file_context.fd,f_file_context.offset,SEEK_SET);
	char packet[1024];
	int bytes = fread(packet,1,sizeof(packet),f_file_context.fd);
	if(bytes < (sizeof(packet))) f_file_context.complete = 1;
	if(bytes > 0){
		//send image(with 4 byte crc)
		int buffer_len = ETH_DATA_PADDING_SIZE + sizeof(struct irom_packet_header) + bytes + 4;
		u8 *buffer = (u8 *)malloc(buffer_len);
		u8 *actual_buf = buffer + ETH_DATA_PADDING_SIZE;
		memset(buffer,0,ETH_DATA_PADDING_SIZE);
		memcpy(actual_buf + sizeof(struct irom_packet_header),packet,bytes);
		//set header
		fill_common_header(actual_buf,FUNC_FLASH_DATA,(u16)(sizeof(struct irom_packet_header) + bytes),f_file_context.seq_no);
		f_file_context.seq_no++;
		//set crc
		fill_crc(actual_buf,buffer_len - ETH_DATA_PADDING_SIZE);
		//send packet
		sendto(socket, (char *)buffer, buffer_len , 0, remoteAddr, addr_len);
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("send packet seqno %d time[%d]\n",f_file_context.seq_no - 1,(int)time(NULL));
		free(buffer);
		f_file_context.offset += bytes;
	}
	return bytes;
}

int eth_send_memory(int socket,struct sockaddr *remoteAddr,int addr_len){
	if(f_file_context.fd == NULL){
		printf("file handle is NULL \n");
		return -1;
	}

	if (f_file_context.address + f_file_context.offset == last_address) {
		printf(" send the same address twice %08x \n", last_address);
		return -1;
	}else{
		last_address = f_file_context.address + f_file_context.offset;
	}

	fseek(f_file_context.fd,f_file_context.offset,SEEK_SET);
	char packet[1024];
	int bytes = fread(packet,1,sizeof(packet),f_file_context.fd);
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("read file  %d offset %d size %d\n",bytes,f_file_context.offset,f_file_context.size);
	if((f_file_context.offset + bytes) >= f_file_context.size){
		fseek(f_file_context.fd,f_file_context.offset,SEEK_SET);
		bytes = fread(packet,1,f_file_context.size - f_file_context.offset,f_file_context.fd);
		f_file_context.complete = 1;
		end_address = last_address;
	}

	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("start send %d\n",bytes);
	if(bytes > 0){
		//send image(with 4 byte crc)
		int buffer_len = ETH_DATA_PADDING_SIZE + sizeof(struct irom_packet_header) + bytes + 4;
		u8 *buffer = (u8 *)malloc(buffer_len);
		u8 *actual_buf = buffer + ETH_DATA_PADDING_SIZE;
		memset(buffer,0,ETH_DATA_PADDING_SIZE);
		memcpy(actual_buf + sizeof(struct irom_packet_header),packet,bytes);
		//set header
		fill_common_header(actual_buf,FUNC_MEM_W,(u16)(sizeof(struct irom_packet_header) + bytes),f_file_context.address + f_file_context.offset);
		//set crc
		fill_crc(actual_buf,buffer_len - ETH_DATA_PADDING_SIZE);
		//send packet
		sendto(socket, (char *)buffer, buffer_len , 0, remoteAddr, addr_len);
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("send packet write address 0x%x size %d time[%d]\n",f_file_context.address + f_file_context.offset,bytes,(int)time(NULL));
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

int broadcast_beacon(int socket1)
{
	int bOpt = 1,len = 0;
	struct sockaddr_in saUdpServ;
	memset(&saUdpServ, 0, sizeof(saUdpServ));
	saUdpServ.sin_family = AF_INET;
	saUdpServ.sin_addr.s_addr=inet_addr("255.255.255.255");
	saUdpServ.sin_port = htons(7001);
	int nSize = sizeof(struct sockaddr_in);

	setsockopt(socket1, SOL_SOCKET, SO_BROADCAST, (char*)&bOpt, sizeof(bOpt));
	switch(g_cmd_args.cmd_type){
		case TYPE_UPDATE:
			eth_send_sync(socket1,(struct sockaddr *)&saUdpServ, nSize,FUNC_SYNC,0);
			break;
		case TYPE_READ_REG:
			eth_send_message(FUNC_REG_R,g_cmd_args.address,socket1,(struct sockaddr *)&saUdpServ,nSize,0,g_cmd_args.width);
			return 1;
		case TYPE_PHY_INIT:
			eth_send_message(FUNC_PHY_INIT,g_cmd_args.address,socket1,(struct sockaddr *)&saUdpServ,nSize,0,0);
			return 1;

		case TYPE_WRITE_REG:
			eth_send_message(FUNC_REG_W,g_cmd_args.address,socket1,(struct sockaddr *)&saUdpServ,nSize,g_cmd_args.value,g_cmd_args.width);
			return 1;

		case TYPE_LOAD_RF_BIN:
			eth_send_message(FUNC_LOAD_RF_BIN,g_cmd_args.address,socket1,(struct sockaddr *)&saUdpServ,nSize,g_cmd_args.len,g_cmd_args.width);
			return 1;

		case TYPE_READ_MEM:
			if(g_cmd_args.len - 1024 < 0)
			  len = g_cmd_args.len;
			else
			  len = 1024;
			if(len > 0){
				eth_send_message(FUNC_MEM_R,g_cmd_args.address,socket1,(struct sockaddr *)&saUdpServ,nSize,len,0);
				g_cmd_args.len -= len;
				g_cmd_args.address += len;
			}else{
				return 1;
			}

			break;
		case TYPE_WRITE_MEM:
			if(!f_file_context.complete)
			  eth_send_memory(socket1,(struct sockaddr *)&saUdpServ,nSize);
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

		case TYPE_GET_VERSION:
			eth_send_message(FUNC_GET_VERSION, VERSION, socket1, (struct sockaddr *)&saUdpServ, nSize, 0, 0);
			return 1;

		case TYPE_MEMSET:
			eth_send_message(FUNC_MEMSET, g_cmd_args.address, socket1, (struct sockaddr *)&saUdpServ, nSize, g_cmd_args.len, 0);
			return 1;
		default :
			if(g_cmd_args.reboot == 1)
			  eth_send_message(FUNC_REBOOT,0,socket1,(struct sockaddr *)&saUdpServ,nSize,0,0);
			else
			  printf("error cmd %d\n",g_cmd_args.cmd_type);

			return 1;
	}

	bOpt = 0;
	//set back
	setsockopt(socket1, SOL_SOCKET, SO_BROADCAST, (char*)&bOpt, sizeof(bOpt));
	return 0;
}

int attach_file()
{
	int ret = 0;
	//close old file if exist
	if(f_file_context.fd != NULL){
		fclose(f_file_context.fd);
		f_file_context.fd = NULL;
	}
	int cur_file_index = f_file_context.index;
	memset(&f_file_context,0,sizeof(struct file_transfer_context));
	f_file_context.index = cur_file_index;
	//if(f_file_context.index >= 0 && f_file_context.index < FILE_ARRAY_SIZE && g_file_list[f_file_context.index].valid){
	if(1){
		f_file_context.fd = fopen(g_file_list[f_file_context.index].path,"rb");
		//f_file_context.fd = fopen(IMAGE_FILE_PATH,"rb");
		if(f_file_context.fd == NULL){
			if(__debug_mode > DEBUG_LVL_SLIENCE) printf("open file %s failed \n",g_file_list[f_file_context.index].path);
			reset_state();
			return -1;
		}
	}else{
		printf("can not open input file--index=%d \n",f_file_context.index);
		reset_state();
		return -1;
	}
	//f_file_context.address = IMAGE_FILE_ADDRESS;
	f_file_context.address = g_file_list[f_file_context.index].address;
	f_file_context.size = g_file_list[f_file_context.index].filesize;
	f_file_context.checksum = g_file_list[f_file_context.index].checksum;
	f_file_context.starttime = time(NULL);
	return ret;
}

int memory_op_init()
{
	int filesize = 0;
	//close old file if exist
	if(f_file_context.fd != NULL){
		fclose(f_file_context.fd);
		f_file_context.fd = NULL;
	}
	memset(&f_file_context,0,sizeof(struct file_transfer_context));
	if(g_cmd_args.cmd_type == TYPE_READ_MEM)
	  f_file_context.fd = fopen(memory_path,"wb");
	else if(g_cmd_args.cmd_type == TYPE_WRITE_MEM)
	  f_file_context.fd = fopen(memory_path,"rb");

	if(f_file_context.fd == NULL){
		printf("open file %s failed \n",g_file_list[f_file_context.index].path);
		return -1;
	}

	f_file_context.address = g_cmd_args.address;
	if(g_cmd_args.cmd_type == TYPE_READ_MEM){
		f_file_context.size = g_cmd_args.len;
	}
	else{
		fseek(f_file_context.fd,0,SEEK_END);
		filesize = ftell(f_file_context.fd);
		if(filesize == 0)
		  return -1;
		else if(filesize < g_cmd_args.len ){
			f_file_context.size = filesize;
			printf("file is smaller then len. use file size %d\n",filesize);
		}else
		  f_file_context.size = g_cmd_args.len;
	}

	return 0;

}

//max length 96K
int dump_memory(int address, char* buf, int len){
	int i = 0;
	for(; i < len; i++){
		if(i % 16 == 0)
		  printf("addr 0x%08x: ",address + i);

		if(i % 4 == 0)
		  printf("0x");

		printf("%02x",(unsigned char)*(buf+i));

		if((i+1) % 4 == 0)
		  printf(" ");

		if((i+1) % 16 == 0)
		  printf("\n");
	}
	printf("\n");
}

int handlePacket(int socket,u8 *packet,int pktlen,struct sockaddr *remoteAddr,int addr_len)
{
	if(pktlen < sizeof(struct irom_packet_header_rx)) return 0;

	struct irom_packet_header_rx *header = (struct irom_packet_header_rx*)(packet);
	if(memcmp(header->identify,DL_INDENTIFY,sizeof(DL_INDENTIFY))){
		*((u8 *)header->identify + sizeof(header->identify)) = 0;
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("unknown packet identify %s\n",(u8 *)header->identify);
		return 0;
	}
	//get cmd
	u16 cmd = htons(header->cmd) & 0xFF;
	u8 err = (u8)((htons(header->cmd) & 0xFF00)  >> 8);
	u16 packet_len = htons(header->packet_len);
	u32 seq_no = htonl(header->seq_no);


	if(err != DL_ACK_OK){
		if(__debug_mode >= DEBUG_LVL_DEBUG){
			if(__debug_mode > DEBUG_LVL_SLIENCE) printf( "receive ack pkt[%s]: ",inet_ntoa(((struct sockaddr_in *)remoteAddr)->sin_addr));
			set_console_color(TEST_COLOR_INDEX_RED);
			if(__debug_mode > DEBUG_LVL_SLIENCE) printf("cmd[0x%x] err[0x%x] ",cmd,err);
			restore_console_color();
			if(__debug_mode > DEBUG_LVL_SLIENCE) printf( "seqno %d ----time[%d]\r\n",seq_no,(int)time(NULL));
		}
	}else{
		//don't printf image ack which cost time
		if(f_state == STATE_WAIT_ADDRESS_ACK) if(__debug_mode > DEBUG_LVL_SLIENCE) printf("\n");
		if(f_state == STATE_WAIT_IMAGE_ACK){
			if(__debug_mode > DEBUG_LVL_SLIENCE) printf("receive ack [%s]: cmd[0x%x]  seqno %d ----time[%d] percent[%3d]%s",
						inet_ntoa(((struct sockaddr_in *)remoteAddr)->sin_addr),cmd,seq_no,(int)time(NULL),
						(f_file_context.size != 0) ? (int)((seq_no * 1024 * 100) / f_file_context.size) : 0,
						(__debug_mode == DEBUG_LVL_SLIENCE) ? "\033[1A\r\n":"\r\n");
		}else{
			if(__debug_mode > DEBUG_LVL_SLIENCE) printf("receive ack [%s]: cmd[0x%x]----time[%d] \r\n",
						inet_ntoa(((struct sockaddr_in *)remoteAddr)->sin_addr),cmd,(int)time(NULL));
		}
	}

	switch(cmd){
		case FUNC_SYNC:
			reset_state();
			//any time connect reset the state
			memcpy(&connect_server_addr,remoteAddr,sizeof(struct sockaddr));
			f_file_context.starttime = time(NULL);
			if(__debug_mode > DEBUG_LVL_SLIENCE) printf("receive sync ack,now start transfer time= %d\n",f_file_context.starttime);
			//too much beacon packet ,wait client ready
			f_state = STATE_WAIT_READY;
			return 0;
		case FUNC_REG_R:
			{
				u32 address= htonl(*(int *)(packet+12));
				printf("read value : 0x%08x address 0x%08x\n",seq_no,address);
				return 1;
			}
		case FUNC_PHY_INIT:
			{
				printf("phy init : value %d\n",seq_no);
				return 1;
			}
		case FUNC_GET_VERSION:
			{
				printf("version get tools %08x firmware %08x\n",VERSION,seq_no);
				return 1;
			}

		case FUNC_MEMSET:
			{
				u32 address= htonl(*(int *)(packet+12));
				printf("mem set len %d address %08x\n",seq_no, address);
				return 1;
			}

		case FUNC_LOAD_RF_BIN:
			{
				u32 address= htonl(*(int *)(packet+12));
				printf("load rf bin len %d address %08x\n",seq_no, address);
				return 1;
			}

		case FUNC_REG_W:
			{
				u32 address= htonl(*(int *)(packet+12));
				printf("write value : 0x%08x address 0x%08x\n",seq_no,address);
				return 1;
			}
		case FUNC_MEM_R:
			{
				char* read_buf = packet + 12;
				int read_len = packet_len -12;
				printf("read   length: %d address 0x%08x\n",read_len, seq_no);
				if(g_cmd_args.print_out)
				  dump_memory( seq_no, read_buf,read_len);

				eth_recv_memory(read_buf,read_len);
				if(f_file_context.complete == 1)
				  return 1;
				return 0;
			}
		case FUNC_MEM_W:
			{
				u32 address= htonl(*(int *)(packet+12));
				printf("write length: %d address %08x\n",seq_no,address);
				if(f_file_context.complete == 1 && end_address == address)
				  return 1;
				return 0;
			}
		case FUNC_IQ_PLAYER_START:
			{
				// 0 = rp init fail 1= already start
				printf("iq_player start iq count %d\n", seq_no);
				return 1;
			}
			break;
		case FUNC_IQ_PLAYER_STOP:
			{
				printf("iq_player stop \n");
				return 1;
			}
			break;
		case FUNC_IQ_RECORD_START:
			{
				// 0 = rp init fail 1= already start
				printf("iq_record start iq count %d\n", seq_no);
				return 1;
			}
		case FUNC_IQ_RECORD_STOP:
			{
				printf("iq_record stop \n");
				return 1;
			}
		case FUNC_REBOOT:
			{
				printf("board reboot\n");
				return 1;
			}

		default:
			break;
	}

	//discard any other message if not connected or address mismatch
	if(f_state == STATE_WAIT_CONNECT || memcmp(&connect_server_addr,remoteAddr,sizeof(struct sockaddr))){
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("not connect yet\n");
		return 0;
	}
	switch(f_state){
		case STATE_WAIT_READY:
			{
				if(cmd == FUNC_READY){
					if(!g_arp_entry_added){
						//trigger arp request,and wait for arp entry add,otherwise we can not send any packet to dest
						eth_send_message(FUNC_SYNC,0,socket,remoteAddr,addr_len,0,0);
						sleep(1);
					}
					if(attach_file() != 0) break;
					//send adress info
					f_state = STATE_WAIT_ADDRESS_ACK;
					eth_send_burn_address(socket,remoteAddr,addr_len);
					if(__debug_mode > DEBUG_LVL_SLIENCE) printf("waiting for address ack,eraseing .");
				}
				break;
			}
		case STATE_WAIT_ADDRESS_ACK:
			{
				//receive address ack
				if(cmd == FUNC_FLASH_START){
					//begin transfer image now
					f_state = STATE_WAIT_IMAGE_ACK;
					transfer_image(socket,remoteAddr,addr_len);
				}
				break;
			}
		case STATE_WAIT_IMAGE_ACK:
			{
				if(cmd == FUNC_FLASH_DATA){
					if(f_file_context.complete == 1){
						eth_send_checksum(socket,remoteAddr,addr_len);
						f_state = STATE_WAIT_CHECKSUM_ACK;
					}else{
						//check ack and send the next image
						int bytes = transfer_image(socket,remoteAddr,addr_len);
						if(bytes == 0){
							if(__debug_mode > DEBUG_LVL_SLIENCE) printf("no more bytes trans over\n");
							eth_send_checksum(socket,remoteAddr,addr_len);
							f_state = STATE_WAIT_CHECKSUM_ACK;
						}
					}
				}
				break;
			}
		case STATE_WAIT_CHECKSUM_ACK:
			{
				if(cmd == FUNC_CHECKSUM){
					//send next packet ?
					if(g_file_list[f_file_context.index + 1].valid && f_file_context.index < FILE_ARRAY_SIZE){
						f_file_context.index++;
						if(attach_file() != 0) break;
						//send adress info
						f_state = STATE_WAIT_ADDRESS_ACK;
						eth_send_burn_address(socket,remoteAddr,addr_len);
					}else{
						eth_send_message(FUNC_FLASH_END,0,socket,remoteAddr,addr_len,0,0);
						f_state = STATE_WAIT_FINISH_ACK;
					}
				}
				break;
			}
		case STATE_WAIT_FINISH_ACK:
			{
				if(cmd == FUNC_FLASH_END){
					printf("transfer success---cost time %d ms\n",(int)time(NULL) - f_file_context.starttime);
					reset_state();
					exit(1);
				}
				break;
			}
		default:{
					if(__debug_mode > DEBUG_LVL_SLIENCE) printf("unknown packet-\n");
				}
	}
	return 0;
}

void getExePath(char *path)
{
	realpath("./",path);
}

u8 cal_file_checksum(FILE *fp)
{
	u8 ret = 0;
	if(fp == NULL) return ret;
	fseek(fp,0,SEEK_SET);
	u8 packet[1024];
	int bytes = 0;
	do{
		bytes = fread(packet,1,sizeof(packet),fp);
		if(bytes > 0){
			int i = 0;
			for(i = 0 ; i < bytes ; i++){
				ret += packet[i];
			}
		}
	}while(bytes > 0);
	return ret;
}

static void usage()
{
	FILE *stream = stdout;

	fprintf(stream,"Usage: -h(show help)\n");
	fprintf(stream,"-v if set , get version of software && hardware\n");
	fprintf(stream,"-d log level use 2 will print debug log\n");
	fprintf(stream,"-r read mode input [hex address] [width/length] [file name]\n");
	fprintf(stream,"-w write mode input [hex address] [width/length] [hex write value] [file name]\n");
	fprintf(stream,"-m memset input[hex address] [len]\n");
	fprintf(stream,"-u update\n");
	fprintf(stream,"-p if set , do phy init with [decimal option] 1 =>phy_init in phy_sim.c 2=>phy_init in phy_aetnensis.c \n");
	fprintf(stream,"-o if set , read memory will print in HEX default is to a file \n");
	fprintf(stream,"-b if set , reboot after exec cmd or directly reboot\n");
	fprintf(stream,"-l load rf pmem bin [hex address] [len][no irq] wait 1s at end, len should be even\n");
	// iq_player start params
	fprintf(stream,"hw select   0 - rf  1 - BB default 0\n");
	fprintf(stream,"band select 0 - low band 1 - high band default 0\n");
	fprintf(stream,"band width  0 - 20Mhz 1 - 40Mhz 2 - 80Mhz default 0\n");
	fprintf(stream,"continuous mode 0 - singe frame 1 - continuous default 0\n");
	fprintf(stream,"IQ count\n");
	fprintf(stream,"-s cmd iq player start [hw select][band select][band width][continuous][iq count]\n");
	fprintf(stream,"-t if set , cmd iq player stop\n");
	fprintf(stream,"-a cmd iq record start [hw select][band select][band width][continuous][iq count]\n");
	fprintf(stream,"-c if set , cmd iq record stop\n");

	fprintf(stream,"for example:\n");
	fprintf(stream,"./SF_ETH_DEBUG_TOOLS  -r 0xb0000000 1\n");
	fprintf(stream,"./SF_ETH_DEBUG_TOOLS  -r 0x1000 0\n");
	fprintf(stream,"./SF_ETH_DEBUG_TOOLS  -w 0xb0000000 2 0x12\n");
	fprintf(stream,"./SF_ETH_DEBUG_TOOLS  -r 0xb0000000 2048 -o\n");
	fprintf(stream,"read / write memory will use memory.bin if not set filename\n");
	fprintf(stream,"./SF_ETH_DEBUG_TOOLS  -w 0xb0000000 2048 123.bin\n");
	fprintf(stream,"./SF_ETH_DEBUG_TOOLS  -s  1 1 2 1 1024\n");
	exit(0);
}

int test(void)
{
	int i = 0;
	for (i=0;i<=100;i++)
	{
		if(__debug_mode > DEBUG_LVL_SLIENCE)  printf("%3d%%\033[1A\r\n",i);
		sleep(1);
	}
	return 0;
}

int main(int argc, char* argv[])
{
	//read file list
	char section_name[20] = {0};
	char exe_path[256] = {0};
	char config_path[400] = {0};


	getExePath(exe_path);
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("module file path = %s\n",exe_path);

	int size1 = 131088;
	int seq_no1 = 0;
	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("--------size = %d %d\n",size1,(int)((seq_no1 * 1024 * 100) / size1));
	memset(&g_cmd_args, 0, sizeof(struct cmd_args_t));
	int32_t n = 0;
	while (n >= 0) {
		n = getopt_long(argc, argv, "d:hr:w:up:bostacvm:l:", NULL, NULL);
		if (n < 0) continue;
		switch (n) {
			case 'd':
				__debug_mode = atoi(optarg);
				break;
			case 'h':
				usage();
				break;
			case 'r':
				g_cmd_args.cmd_type = TYPE_READ_REG;
				g_cmd_args.address = strtoul(optarg,NULL,16);
				break;
			case 'l':
				g_cmd_args.cmd_type = TYPE_LOAD_RF_BIN;
				g_cmd_args.address = strtoul(optarg,NULL,16);
				break;
			case 'w':
				g_cmd_args.cmd_type = TYPE_WRITE_REG;
				g_cmd_args.address = strtoul(optarg,NULL,16);
				break;
			case 'm':
				g_cmd_args.cmd_type = TYPE_MEMSET;
				g_cmd_args.address = strtoul(optarg,NULL,16);
				break;
			case 'v':
				g_cmd_args.cmd_type = TYPE_GET_VERSION;
				break;
			case 'u':
				g_cmd_args.cmd_type = TYPE_UPDATE;
				break;
			case 'b':
				g_cmd_args.reboot= 1;
				break;
			case 'o':
				g_cmd_args.print_out = 1;
				break;
			case 'p':
				g_cmd_args.cmd_type = TYPE_PHY_INIT;
				g_cmd_args.address = atoi(optarg);
				break;
			case 's':
				g_cmd_args.cmd_type = TYPE_IQ_PLAYER_START;
				break;
			case 't':
				g_cmd_args.cmd_type = TYPE_IQ_PLAYER_STOP;
				break;
			case 'a':
				g_cmd_args.cmd_type = TYPE_IQ_RECORD_START;
				break;
			case 'c':
				g_cmd_args.cmd_type = TYPE_IQ_RECORD_STOP;
				break;
			default:
				break;
		}
	}

	argc -= optind;
	argv += optind;
	switch (g_cmd_args.cmd_type){
		case TYPE_READ_REG:
		case TYPE_WRITE_REG:
			if(argc > 0){
				int value = atoi(argv[0]);
				if( value > 3 ){
					g_cmd_args.len= value;
					if(g_cmd_args.cmd_type == TYPE_READ_REG)
					  g_cmd_args.cmd_type = TYPE_READ_MEM;
					else
					  g_cmd_args.cmd_type = TYPE_WRITE_MEM;
					if(argc > 1)
					  sprintf(memory_path,"%s/%s",exe_path,(char*)argv[1]);
					else
					  sprintf(memory_path,"%s/memory.bin",exe_path);
				}
				else if(value >= 0){
					g_cmd_args.width= value;
					if(g_cmd_args.cmd_type == TYPE_WRITE_REG)
					  g_cmd_args.value = strtoul(argv[1],NULL,16);
				}
				else {
					printf("err args cmd %d value %d\n",g_cmd_args.cmd_type, value);
					return -1;
				}
			}else{
				printf("err args num for read/write\n");
				return -1;
			}
			break;
		case TYPE_IQ_PLAYER_START:
		case TYPE_IQ_RECORD_START:
			if(argc != 5){
				printf("err args num %d\n",argc);
				return -1;
			}
			g_cmd_args.hw_sel		= atoi(argv[0]);
			g_cmd_args.band_sel		= atoi(argv[1]);
			g_cmd_args.band_width		= atoi(argv[2]);
			g_cmd_args.continuous		= atoi(argv[3]);
			g_cmd_args.iq_count		= atoi(argv[4]);
			break;

		case TYPE_MEMSET:
			g_cmd_args.len = atoi(argv[0]);
			break;

		case TYPE_LOAD_RF_BIN:
			g_cmd_args.len = atoi(argv[0]);
			g_cmd_args.width = atoi(argv[1]);
			break;
		default:
			break;
	};

	if(g_cmd_args.cmd_type == TYPE_READ_REG || g_cmd_args.cmd_type == TYPE_WRITE_REG){
		if( (g_cmd_args.address >> 28) == 0 && (g_cmd_args.width != 0)){
			printf("address invalid\n");
			return -1;
		}
	}else if (g_cmd_args.cmd_type == TYPE_IQ_PLAYER_START) {
		if (g_cmd_args.iq_count == 0) {
			printf("error args iq start with out iq count\n");
			return -1;
		}
	}


	if(__debug_mode > DEBUG_LVL_SLIENCE) printf("cmd is %d address is 0x%x  len is %d value is %d\n",g_cmd_args.cmd_type,(int)g_cmd_args.address,g_cmd_args.len,(int)g_cmd_args.value);



	if(g_cmd_args.cmd_type == TYPE_UPDATE){
		sprintf(config_path,"%s/config.ini",exe_path);
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("config_path=%s\n",config_path);

		int i = 0;
		int validcount = 0;
		char file_burn_address[20];
		char file_name[100];

		for(i = 1; i <= FILE_ARRAY_SIZE;i++){
			memset((char *)(&g_file_list[i-1]),0,sizeof(g_file_list[i-1]));
			sprintf(section_name,"file%d",i);
#if 0
			int ret1 = GetPrivateProfileStringA(section_name,"file","",file_name,sizeof(file_name),config_path);
			int ret2 = GetPrivateProfileStringA(section_name,"address","",file_burn_address,sizeof(file_burn_address),config_path);
#else
			memset(file_name,0,sizeof(file_name));
			memset(file_burn_address,0,sizeof(file_burn_address));
			int ret1 = ConfigGetKey(config_path, section_name,"file",file_name);
			int ret2 = ConfigGetKey(config_path,section_name,"address",file_burn_address);
#endif
			if(strlen(file_name) != 0 && strlen(file_burn_address) != 0){
				sprintf(g_file_list[i-1].path,"%s/%s",exe_path,file_name);
				//get file size
				FILE *fp = fopen(g_file_list[i-1].path,"rb");
				if(fp != NULL){
					//g_file_list[i-1].address = file_burn_address
					char *stop = 0;
					g_file_list[i-1].address = strtoul(file_burn_address,&stop,16);
					fseek(fp,0,SEEK_END);
					g_file_list[i-1].valid = 1;
					validcount++;
					g_file_list[i-1].filesize = ftell(fp);
					g_file_list[i-1].checksum = cal_file_checksum(fp);
					fclose(fp);
					set_console_color(TEST_COLOR_INDEX_GREEN);
					if(__debug_mode > DEBUG_LVL_SLIENCE) printf("get config path=%s address=0x%x size =%d checksum=0x%x\n",
								g_file_list[i-1].path,g_file_list[i-1].address,g_file_list[i-1].filesize,g_file_list[i-1].checksum);
					restore_console_color();
				}else{
					if(__debug_mode > DEBUG_LVL_SLIENCE) printf("can not open file %s\n",g_file_list[i-1].path);
				}
			}
		}

		if(!validcount){
			if(__debug_mode > DEBUG_LVL_SLIENCE) printf("please edit bin address and path with config.ini\nexit now...\n");
			char c;
			scanf("%c",&c);
			return 0;
		}

	}
	else{
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("memory_path=%s\n",memory_path);
		if(g_cmd_args.cmd_type == TYPE_WRITE_MEM || g_cmd_args.cmd_type == TYPE_READ_MEM){
			if(memory_op_init() <0){
				if(__debug_mode > DEBUG_LVL_SLIENCE) printf("init memory file failed \n");
				return -1;
			}
		}
	}
	//init,reset state
	g_arp_entry_added = 0;

	int serSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(serSocket < 0)
	{
		if(__debug_mode > DEBUG_LVL_SLIENCE) printf("socket error !\n");
		return 0;
	}

	struct sockaddr_in serAddr;
	serAddr.sin_family = AF_INET;
	//serAddr.sin_port = htons(13568);
	serAddr.sin_port = htons(6789);
	serAddr.sin_addr.s_addr=htonl(INADDR_ANY);
	if(bind(serSocket, (struct sockaddr *)&serAddr, sizeof(serAddr)) < 0)
	{
		printf("bind error !");
		close(serSocket);
		return 0;
	}
	//set read time out
#if 0
	int timeou_ms = 10;
	setsockopt(serSocket,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeou_ms,sizeof(timeou_ms));
#else
	struct timeval timeout={0,200000};
	setsockopt(serSocket,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(struct timeval));
#endif
	if(__debug_mode > DEBUG_LVL_SLIENCE) if(__debug_mode > DEBUG_LVL_SLIENCE) printf("bind start at socket %d!\n",serSocket);

	struct sockaddr_in remoteAddr;
	int nAddrLen = sizeof(remoteAddr);
	while(1)
	{
		char recvData[2000];
		int ret = recvfrom(serSocket, recvData, 2000, 0, (struct sockaddr *)&remoteAddr, &nAddrLen);
		if (ret > 0)
		{
			recvData[ret] = 0x00;
			if(handlePacket(serSocket,(u8 *)recvData,ret,(struct sockaddr *)&remoteAddr,nAddrLen) > 0)
			  break;
		}else{
			//timeout
			if(f_state == STATE_WAIT_CONNECT && f_state != STATE_NOT_BROADCAST){
				if(broadcast_beacon(serSocket) == 1)
				  f_state = STATE_NOT_BROADCAST;

			}else if(f_state == STATE_WAIT_READY){
			}else if(f_state == STATE_WAIT_ADDRESS_ACK){
				//this step cost much time
				printf(" .");
				fflush(stdout);
			}else{
			}
		}
	}
	//here used for reboot after execute cmd
	if(g_cmd_args.reboot){
		eth_send_message(FUNC_REBOOT,0,serSocket,(struct sockaddr *)&remoteAddr,nAddrLen,0,0);
		printf("send reboot \n");
	}

	close(serSocket);
	if(f_file_context.fd != NULL)
	  fclose(f_file_context.fd);
	return 0;
}
