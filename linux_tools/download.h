#ifndef _DOWNLOAD_H__
#define __DOWNLOAD_H__

typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned short u16;

/* ---------------------type define------------------------------------------ */
#define FUNC_SYNC		        0x80  //sync to PC.
#define FUNC_READY		        0x81  //eth to clear FIFO.
#define FUNC_FLASH_START        0x82  //get the bin address we need to download.
#define FUNC_FLASH_DATA         0x83  //get the length of the bin.
#define FUNC_FLASH_END          0x84  //get the package of the data.
#define FUNC_CHECKSUM           0x85  //compare the checksum to judge if the download data transfer is right.
#define FUNC_REG_R              0x86  //reg read
#define FUNC_REG_W              0x87  //reg_write
#define FUNC_MEM_R              0x88  //mem_read
#define FUNC_MEM_W              0x89  //mem_write
#define FUNC_REBOOT             0x90  //reboot
#define FUNC_PHY_INIT           0x91  //reboot
#define FUNC_IQ_PLAYER_START    0x92  //iq player
#define FUNC_IQ_PLAYER_STOP     0x93  //iq player
#define FUNC_IQ_RECORD_START    0x94  //iq record
#define FUNC_IQ_RECORD_STOP     0x95  //iq record
#define FUNC_GET_VERSION        0x96  //get version
#define FUNC_MEMSET				0x97  //memset
#define FUNC_LOAD_RF_BIN		0x99//load firmware bin
#define FUNC_ACK_C              0x98  //when receive wrong (len or cmd),will send this ack
#define FUNC_MAX                0x100

#define DL_ERROR_CRC			1
#define DL_ERROR_FRAME			2
#define DL_ERROR_LENGTH			3
#define DL_ERROR_OVERFLOW		4
#define DL_ERROR_TIMEOUT		5

//bytes
#define PKG_HEAD_SIZE           4
#define PKG_LEN_SIZE            2
#define PKG_CMD_SIZE            2
#define PKG_INDEX_SIZE          4
#define PKG_CRC_SIZE            4
#define PKG_DATA_MAX_SIZE       1024
#define DL_PKG_MIN_SIZE         (PKG_HEAD_SIZE + PKG_LEN_SIZE + PKG_CMD_SIZE + PKG_INDEX_SIZE + PKG_CRC_SIZE)
#define DL_PKG_MAX_SIZE         (DL_PKG_MIN_SIZE + PKG_DATA_MAX_SIZE)


#define DL_SYNC_HEAD_CODE       0xaa44bbdd
#define DL_SYNC_RETRY_TIMES     4
#define DL_PKG_SYNC_TIMEOUT     10
#define DL_PKG_NORMAL_TIMEOUT   4
#define DL_RECEIVE_RETRY_TIMES  4

#define DL_ACK_FAIL_PKG         1
#define DL_ACK_FAIL_PKG_HEAD    2
#define DL_ACK_FAIL_PKG_LEN     3
#define DL_ACK_FAIL_PKG_CMD     4
#define DL_ACK_FAIL_PKG_CRC     5
#define DL_ACK_FAIL_PKG_NO      6
#define DL_ACK_FAIL_BIN_LEN     7
#define DL_ACK_FAIL_BIN_CHK     8
#define DL_ACK_OK				0


typedef struct Package_t{
	u32 pkg_len;
	u32 cmd;
	u32 pkg_number;
	u32 crc;
	u8 buff[PKG_DATA_MAX_SIZE];
}Dl_Package;


typedef struct Bin_info_t{
	u32 bin_addr;
	u32 bin_len;
	u32 pkg_no;
	u32 checksum;
	u8  sector_buff[PKG_DATA_MAX_SIZE*4];
}Dl_Bin_info;


#endif //__DL_H__
