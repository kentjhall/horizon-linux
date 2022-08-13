#ifndef UAPI_SCSI_UFS_UFS_IOCTL_H_
#define UAPI_SCSI_UFS_UFS_IOCTL_H_

#include <linux/types.h>

/*
 *  IOCTL opcode for ufs combo queries has the following opcode after
 *  SCSI_IOCTL_GET_PCI
 */
#define UFS_IOCTL_COMBO_QUERY           0x5388
/*
 *  IOCTL opcode to set UFS power mode
 */
#define UFS_IOCTL_SET_POWER_MODE        0x5389

/*
 * Maximum number of Query requests per Combo Query Request
 */
#define MAX_QUERY_CMD_PER_COMBO         10

/**
 * struct ufs_ioc_query_cmd - used to transfer ufs query command/data to and
 * from user via ioctl
 */
struct ufs_ioc_query_req {
	/* Query opcode to specify the type of Query operation */
	__u8 opcode;
	/* idn to provide more info on specific operation. */
	__u8 idn;
	/* index - optional in some cases */
	__u8 index;
	/* index - optional in some cases */
	__u8 selector;
	/* buf_size - buffer size in bytes pointed by buffer. */
	__u16 buf_size;
	/*
	 * user buffer pointer for query data.
	 * Note:
	 * For Read/Write Attribute this should be of 4 bytes
	 * For Read Flag this should be of 1 byte
	 * For Descriptor Read/Write size depends on the type of the descriptor
	 */
	__u8 *buffer;
	/* delay after query command completion */
	__u32 delay;
	/* error status for the query operation */
	__s32 error_status;
};


struct ufs_ioc_combo_query_req {
	/* Number of Query Commands in this Combo */
	__u8 num_cmds;
	/* Flag to Specify if Command Queue need to be empty or not */
	__u8 need_cq_empty;
	/* Flag to Specify if return or continue with all requests on error */
	__u8 return_on_error;
	/* pointer to the first query command request */
	struct ufs_ioc_query_req *query;
};

#endif /* UAPI_SCSI_UFS_UFS_IOCTL_H_ */
