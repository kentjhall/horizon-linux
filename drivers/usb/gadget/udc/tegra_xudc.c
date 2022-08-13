/*
* NVIDIA XUSB device mode controller
*
* Copyright (c) 2013-2021, NVIDIA CORPORATION.  All rights reserved.
* Copyright (c) 2015, Google Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms and conditions of the GNU General Public License,
* version 2, as published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/extcon.h>
#include <linux/interrupt.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/phy/phy.h>
#include <linux/phy/tegra/xusb.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>
#include <linux/tegra-powergate.h>
#include <linux/tegra_pm_domains.h>
#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>
#include <linux/usb/tegra_usb_charger.h>
#include <linux/workqueue.h>
#include <linux/pm_qos.h>
#include <soc/tegra/chip-id.h>
#include <linux/platform/tegra/emc_bwmgr.h>

/* XUSB_DEV registers */
#define SPARAM 0x000
#define  SPARAM_ERSTMAX_SHIFT 16
#define  SPARAM_ERSTMAX_MASK 0x1f
#define DB 0x004
#define  DB_TARGET_SHIFT 8
#define  DB_TARGET_MASK 0xff
#define  DB_STREAMID_SHIFT 16
#define  DB_STREAMID_MASK 0xffff
#define ERSTSZ 0x008
#define  ERSTSZ_ERSTXSZ_SHIFT(x) ((x) * 16)
#define  ERSTSZ_ERSTXSZ_MASK 0xffff
#define ERSTXBALO(x) (0x010 + 8 * (x))
#define ERSTXBAHI(x) (0x014 + 8 * (x))
#define ERDPLO 0x020
#define  ERDPLO_EHB BIT(3)
#define ERDPHI 0x024
#define EREPLO 0x028
#define  EREPLO_ECS BIT(0)
#define  EREPLO_SEGI BIT(1)
#define EREPHI 0x02c
#define CTRL 0x030
#define  CTRL_RUN BIT(0)
#define  CTRL_LSE BIT(1)
#define  CTRL_IE BIT(4)
#define  CTRL_SMI_EVT BIT(5)
#define  CTRL_SMI_DSE BIT(6)
#define  CTRL_EWE BIT(7)
#define  CTRL_DEVADDR_SHIFT 24
#define  CTRL_DEVADDR_MASK 0x7f
#define  CTRL_ENABLE BIT(31)
#define ST 0x034
#define  ST_RC BIT(0)
#define  ST_IP BIT(4)
#define RT_IMOD	0x038
#define  RT_IMOD_IMODI_SHIFT 0
#define  RT_IMOD_IMODI_MASK 0xffff
#define  RT_IMOD_IMODC_SHIFT 16
#define  RT_IMOD_IMODC_MASK 0xffff
#define PORTSC 0x03c
#define  PORTSC_CCS BIT(0)
#define  PORTSC_PED BIT(1)
#define  PORTSC_PR BIT(4)
#define  PORTSC_PLS_SHIFT 5
#define  PORTSC_PLS_MASK 0xf
#define  PORTSC_PLS_U0 0x0
#define  PORTSC_PLS_U2 0x2
#define  PORTSC_PLS_U3 0x3
#define  PORTSC_PLS_DISABLED 0x4
#define  PORTSC_PLS_RXDETECT 0x5
#define  PORTSC_PLS_INACTIVE 0x6
#define  PORTSC_PLS_RESUME 0xf
#define  PORTSC_PS_SHIFT 10
#define  PORTSC_PS_MASK 0xf
#define  PORTSC_PS_UNDEFINED 0x0
#define  PORTSC_PS_FS 0x1
#define  PORTSC_PS_LS 0x2
#define  PORTSC_PS_HS 0x3
#define  PORTSC_PS_SS 0x4
#define  PORTSC_LWS BIT(16)
#define  PORTSC_CSC BIT(17)
#define  PORTSC_WRC BIT(19)
#define  PORTSC_PRC BIT(21)
#define  PORTSC_PLC BIT(22)
#define  PORTSC_CEC BIT(23)
#define  PORTSC_WPR BIT(30)
#define  PORTSC_CHANGE_MASK (PORTSC_CSC | PORTSC_WRC | PORTSC_PRC | \
			     PORTSC_PLC | PORTSC_CEC)
#define ECPLO 0x040
#define ECPHI 0x044
#define MFINDEX 0x048
#define  MFINDEX_UFRAME_SHIFT 0
#define  MFINDEX_UFRAME_MASK 0x7
#define  MFINDEX_FRAME_SHIFT 3
#define  MFINDEX_FRAME_MASK 0x7ff
#define PORTPM 0x04c
#define  PORTPM_L1S_SHIFT 0
#define  PORTPM_L1S_MASK 0x3
#define  PORTPM_L1S_DROP 0x0
#define  PORTPM_L1S_ACCEPT 0x1
#define  PORTPM_L1S_NYET 0x2
#define  PORTPM_L1S_STALL 0x3
#define  PORTPM_RWE BIT(3)
#define  PORTPM_U2TIMEOUT_SHIFT 8
#define  PORTPM_U2TIMEOUT_MASK 0xff
#define  PORTPM_U1TIMEOUT_SHIFT 16
#define  PORTPM_U1TIMEOUT_MASK 0xff
#define  PORTPM_FLA BIT(24)
#define  PORTPM_VBA BIT(25)
#define  PORTPM_WOC BIT(26)
#define  PORTPM_WOD BIT(27)
#define  PORTPM_U1E BIT(28)
#define  PORTPM_U2E BIT(29)
#define  PORTPM_FRWE BIT(30)
#define  PORTPM_PNG_CYA BIT(31)
#define EP_HALT 0x050
#define EP_PAUSE 0x054
#define EP_RELOAD 0x058
#define EP_STCHG 0x05c
#define DEVNOTIF_LO 0x064
#define  DEVNOTIF_LO_TRIG BIT(0)
#define  DEVNOTIF_LO_TYPE_SHIFT 4
#define  DEVNOTIF_LO_TYPE_MASK 0xf
#define  DEVNOTIF_LO_TYPE_FUNCTION_WAKE 0x1
#define DEVNOTIF_HI 0x068
#define PORTHALT 0x06c
#define  PORTHALT_HALT_LTSSM BIT(0)
#define  PORTHALT_HALT_REJECT BIT(1)
#define  PORTHALT_STCHG_REQ BIT(20)
#define  PORTHALT_STCHG_INTR_EN BIT(24)
#define PORT_TM	0x070
#define EP_THREAD_ACTIVE 0x074
#define EP_STOPPED 0x078
#define HSFSPI_COUNT0 0x100
#define HSFSPI_COUNT13 0x134
#define  HSFSPI_COUNT13_U2_RESUME_K_DURATION_SHIFT 0
#define  HSFSPI_COUNT13_U2_RESUME_K_DURATION_MASK 0x3fffffff
#define HSFSPI_COUNT16 0x19c
#define SSPX_CORE_CNT0 0x610
#define  SSPX_CORE_CNT0_PING_TBURST_SHIFT 0
#define  SSPX_CORE_CNT0_PING_TBURST_MASK 0xff
#define SSPX_CORE_CNT30 0x688
#define  SSPX_CORE_CNT30_LMPITP_TIMER_SHIFT 0
#define  SSPX_CORE_CNT30_LMPITP_TIMER_MASK 0xfffff
#define SSPX_CORE_CNT32 0x690
#define  SSPX_CORE_CNT32_POLL_TBURST_MAX_SHIFT 0
#define  SSPX_CORE_CNT32_POLL_TBURST_MAX_MASK 0xff
#define SSPX_CORE_CNT56 0x6fc
#define  SSPX_CORE_CNT56_SCD_BIT0_TRPT_MAX_SHIFT 0
#define  SSPX_CORE_CNT56_SCD_BIT0_TRPT_MAX_MASK 0xfffff
#define SSPX_CORE_CNT57 0x700
#define  SSPX_CORE_CNT57_SCD_BIT1_TRPT_MAX_SHIFT 0
#define  SSPX_CORE_CNT57_SCD_BIT1_TRPT_MAX_MASK 0xfffff
#define SSPX_CORE_CNT65 0x720
#define  SSPX_CORE_CNT65_TX_SCD_END_TRPT_MID_SHIFT 0
#define  SSPX_CORE_CNT65_TX_SCD_END_TRPT_MID_MASK 0xfffff
#define SSPX_CORE_CNT66 0x724
#define  SSPX_CORE_CNT66_TX_SCD_BIT0_TRPT_MID_SHIFT 0
#define  SSPX_CORE_CNT66_TX_SCD_BIT0_TRPT_MID_MASK 0xfffff
#define SSPX_CORE_CNT67 0x728
#define  SSPX_CORE_CNT67_TX_SCD_BIT1_TRPT_MID_SHIFT 0
#define  SSPX_CORE_CNT67_TX_SCD_BIT1_TRPT_MID_MASK 0xfffff
#define SSPX_CORE_CNT72 0x73c
#define  SSPX_CORE_CNT72_SCD_LFPS_TIMEOUT_SHIFT 0
#define  SSPX_CORE_CNT72_SCD_LFPS_TIMEOUT_MASK 0xfffff
#define SSPX_CORE_PADCTL4 0x750
#define  SSPX_CORE_PADCTL4_RXDAT_VLD_TIMEOUT_U3_SHIFT 0
#define  SSPX_CORE_PADCTL4_RXDAT_VLD_TIMEOUT_U3_MASK 0xfffff
#define BLCG 0x840
#define  BLCG_DFPCI BIT(0)
#define  BLCG_UFPCI BIT(1)
#define  BLCG_FE BIT(2)
#define  BLCG_COREPLL_PWRDN BIT(8)
#define  BLCG_IOPLL_0_PWRDN BIT(9)
#define  BLCG_IOPLL_1_PWRDN BIT(10)
#define  BLCG_IOPLL_2_PWRDN BIT(11)
#define  BLCG_ALL 0x1ff
#define CFG_DEV_SSPI_XFER 0x858
#define  CFG_DEV_SSPI_XFER_ACKTIMEOUT_SHIFT 0
#define  CFG_DEV_SSPI_XFER_ACKTIMEOUT_MASK 0xffffffff
#define CFG_DEV_FE 0x85c
#define  CFG_DEV_FE_PORTREGSEL_SHIFT 0
#define  CFG_DEV_FE_PORTREGSEL_MASK 0x3
#define  CFG_DEV_FE_PORTREGSEL_SS_PI 1
#define  CFG_DEV_FE_PORTREGSEL_HSFS_PI 2
#define  CFG_DEV_FE_INFINITE_SS_RETRY BIT(29)

/* FPCI registers */
#define XUSB_DEV_CFG_1 0x004
#define  XUSB_DEV_CFG_1_IO_SPACE_EN BIT(0)
#define  XUSB_DEV_CFG_1_MEMORY_SPACE_EN BIT(1)
#define  XUSB_DEV_CFG_1_BUS_MASTER_EN BIT(2)
#define XUSB_DEV_CFG_4 0x010
#define  XUSB_DEV_CFG_4_BASE_ADDR_SHIFT 15
#define  XUSB_DEV_CFG_4_BASE_ADDR_MASK 0x1ffff
#define XUSB_DEV_CFG_5 0x014

/* IPFS registers */
#define IPFS_XUSB_DEV_CONFIGURATION 0x180
#define  IPFS_XUSB_DEV_CONFIGURATION_EN_FPCI BIT(0)
#define IPFS_XUSB_DEV_INTR_MASK 0x188
#define  IPFS_XUSB_DEV_INTR_MASK_IP_INT_MASK BIT(16)

/* Device ID */
#define XUDC_DEVICE_ID_T210     0x0fad
#define XUDC_DEVICE_ID_T186     0x10e2
#define XUDC_DEVICE_ID_T194     0x10ff

/* Default parameters for boosting EMC/CPU frequency */
#define XUDC_EMC_MAX_FREQ	150000000		/* 150 MHz	*/
#define BOOST_TRIGGER		16384			/* 16 KB	*/
#define EMC_RESTORE_DELAY	msecs_to_jiffies(2*1000)/* 2 sec	*/
#define CPU_BOOST_TIMEOUT	2000

#define XUDC_IS_T210(t) \
	(t->soc ? (t->soc->device_id == XUDC_DEVICE_ID_T210) : false)
#define XUDC_IS_T186(t) \
	(t->soc ? (t->soc->device_id == XUDC_DEVICE_ID_T186) : false)
#define XUDC_IS_T194(t) \
	(t->soc ? (t->soc->device_id == XUDC_DEVICE_ID_T194) : false)

#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
static struct of_device_id tegra_xusba_pd[] = {
	{ .compatible = "nvidia,tegra194-xusba-pd", },
	{ .compatible = "nvidia,tegra186-xusba-pd", },
	{ .compatible = "nvidia,tegra210-xusba-pd", },
	{ .compatible = "nvidia,tegra132-xusba-pd", },
	{},
};

static struct of_device_id tegra_xusbb_pd[] = {
	{ .compatible = "nvidia,tegra194-xusbb-pd", },
	{ .compatible = "nvidia,tegra186-xusbb-pd", },
	{ .compatible = "nvidia,tegra210-xusbb-pd", },
	{ .compatible = "nvidia,tegra132-xusbb-pd", },
	{},
};
#endif

struct tegra_xudc_ep_context {
	__le32 info0;
	__le32 info1;
	__le32 deq_lo;
	__le32 deq_hi;
	__le32 tx_info;
	__le32 rsvd[11];
};

#define EP_STATE_DISABLED 0
#define EP_STATE_RUNNING 1
#define EP_STATE_HALTED 2
#define EP_STATE_STOPPED 3
#define EP_STATE_ERROR 4

#define EP_TYPE_INVALID 0
#define EP_TYPE_ISOCH_OUT 1
#define EP_TYPE_BULK_OUT 2
#define EP_TYPE_INTERRUPT_OUT 3
#define EP_TYPE_CONTROL 4
#define EP_TYPE_ISCOH_IN 5
#define EP_TYPE_BULK_IN 6
#define EP_TYPE_INTERRUPT_IN 7

#define BUILD_EP_CONTEXT_RW(name, member, shift, mask)			\
static inline u32 ep_ctx_read_##name(struct tegra_xudc_ep_context *ctx)	\
{									\
	return (le32_to_cpu(ctx->member) >> shift) & mask;		\
}									\
static inline void							\
ep_ctx_write_##name(struct tegra_xudc_ep_context *ctx, u32 val)		\
{									\
	u32 tmp;							\
									\
	tmp = le32_to_cpu(ctx->member) & ~(mask << shift);		\
	tmp |= (val & mask) << shift;					\
	ctx->member = cpu_to_le32(tmp);					\
}

BUILD_EP_CONTEXT_RW(state, info0, 0, 0x7)
BUILD_EP_CONTEXT_RW(mult, info0, 8, 0x3)
BUILD_EP_CONTEXT_RW(max_pstreams, info0, 10, 0x1f)
BUILD_EP_CONTEXT_RW(lsa, info0, 15, 0x1)
BUILD_EP_CONTEXT_RW(interval, info0, 16, 0xff)
BUILD_EP_CONTEXT_RW(cerr, info1, 1, 0x3)
BUILD_EP_CONTEXT_RW(type, info1, 3, 0x7)
BUILD_EP_CONTEXT_RW(hid, info1, 7, 0x1)
BUILD_EP_CONTEXT_RW(max_burst_size, info1, 8, 0xff)
BUILD_EP_CONTEXT_RW(max_packet_size, info1, 16, 0xffff)
BUILD_EP_CONTEXT_RW(dcs, deq_lo, 0, 0x1)
BUILD_EP_CONTEXT_RW(deq_lo, deq_lo, 4, 0xfffffff)
BUILD_EP_CONTEXT_RW(deq_hi, deq_hi, 0, 0xffffffff)
BUILD_EP_CONTEXT_RW(avg_trb_len, tx_info, 0, 0xffff)
BUILD_EP_CONTEXT_RW(max_esit_payload, tx_info, 16, 0xffff)
BUILD_EP_CONTEXT_RW(edtla, rsvd[0], 0, 0xffffff)
BUILD_EP_CONTEXT_RW(rsvd, rsvd[0], 24, 0x1)
BUILD_EP_CONTEXT_RW(partial_td, rsvd[0], 25, 0x1)
BUILD_EP_CONTEXT_RW(splitxstate, rsvd[0], 26, 0x1)
BUILD_EP_CONTEXT_RW(seq_num, rsvd[0], 27, 0x1f)
BUILD_EP_CONTEXT_RW(cerrcnt, rsvd[1], 18, 0x3)
BUILD_EP_CONTEXT_RW(data_offset, rsvd[2], 0, 0x1ffff)
BUILD_EP_CONTEXT_RW(numtrbs, rsvd[2], 22, 0x1f)
BUILD_EP_CONTEXT_RW(devaddr, rsvd[6], 0, 0x7f)

static inline u64 ep_ctx_read_deq_ptr(struct tegra_xudc_ep_context *ctx)
{
	return ((u64)ep_ctx_read_deq_hi(ctx) << 32) |
		(ep_ctx_read_deq_lo(ctx) << 4);
}

static inline void
ep_ctx_write_deq_ptr(struct tegra_xudc_ep_context *ctx, u64 addr)
{
	ep_ctx_write_deq_lo(ctx, lower_32_bits(addr) >> 4);
	ep_ctx_write_deq_hi(ctx, upper_32_bits(addr));
}

struct tegra_xudc_trb {
	__le32 data_lo;
	__le32 data_hi;
	__le32 status;
	__le32 control;
};

#define TRB_TYPE_RSVD 0
#define TRB_TYPE_NORMAL 1
#define TRB_TYPE_SETUP_STAGE 2
#define TRB_TYPE_DATA_STAGE 3
#define TRB_TYPE_STATUS_STAGE 4
#define TRB_TYPE_ISOCH 5
#define TRB_TYPE_LINK 6
#define TRB_TYPE_TRANSFER_EVENT 32
#define TRB_TYPE_PORT_STATUS_CHANGE_EVENT 34
#define TRB_TYPE_STREAM 48
#define TRB_TYPE_SETUP_PACKET_EVENT 63

#define TRB_CMPL_CODE_INVALID 0
#define TRB_CMPL_CODE_SUCCESS 1
#define TRB_CMPL_CODE_DATA_BUFFER_ERR 2
#define TRB_CMPL_CODE_BABBLE_DETECTED_ERR 3
#define TRB_CMPL_CODE_USB_TRANS_ERR 4
#define TRB_CMPL_CODE_TRB_ERR 5
#define TRB_CMPL_CODE_STALL 6
#define TRB_CMPL_CODE_INVALID_STREAM_TYPE_ERR 10
#define TRB_CMPL_CODE_SHORT_PACKET 13
#define TRB_CMPL_CODE_RING_UNDERRUN 14
#define TRB_CMPL_CODE_RING_OVERRUN 15
#define TRB_CMPL_CODE_EVENT_RING_FULL_ERR 21
#define TRB_CMPL_CODE_STOPPED 26
#define TRB_CMPL_CODE_ISOCH_BUFFER_OVERRUN 31
#define TRB_CMPL_CODE_STREAM_NUMP_ERROR 219
#define TRB_CMPL_CODE_PRIME_PIPE_RECEIVED 220
#define TRB_CMPL_CODE_HOST_REJECTED 221
#define TRB_CMPL_CODE_CTRL_DIR_ERR 222
#define TRB_CMPL_CODE_CTRL_SEQNUM_ERR 223

#define BUILD_TRB_RW(name, member, shift, mask)				\
static inline u32 trb_read_##name(struct tegra_xudc_trb *trb)		\
{									\
	return (le32_to_cpu(trb->member) >> shift) & mask;		\
}									\
static inline void							\
trb_write_##name(struct tegra_xudc_trb *trb, u32 val)			\
{									\
	u32 tmp;							\
									\
	tmp = le32_to_cpu(trb->member) & ~(mask << shift);		\
	tmp |= (val & mask) << shift;					\
	trb->member = cpu_to_le32(tmp);					\
}

BUILD_TRB_RW(data_lo, data_lo, 0, 0xffffffff)
BUILD_TRB_RW(data_hi, data_hi, 0, 0xffffffff)
BUILD_TRB_RW(seq_num, status, 0, 0xffff)
BUILD_TRB_RW(transfer_len, status, 0, 0xffffff)
BUILD_TRB_RW(td_size, status, 17, 0x1f)
BUILD_TRB_RW(cmpl_code, status, 24, 0xff)
BUILD_TRB_RW(cycle, control, 0, 0x1)
BUILD_TRB_RW(toggle_cycle, control, 1, 0x1)
BUILD_TRB_RW(isp, control, 2, 0x1)
BUILD_TRB_RW(chain, control, 4, 0x1)
BUILD_TRB_RW(ioc, control, 5, 0x1)
BUILD_TRB_RW(type, control, 10, 0x3f)
BUILD_TRB_RW(stream_id, control, 16, 0xffff)
BUILD_TRB_RW(endpoint_id, control, 16, 0x1f)
BUILD_TRB_RW(tlbpc, control, 16, 0xf)
BUILD_TRB_RW(data_stage_dir, control, 16, 0x1)
BUILD_TRB_RW(frame_id, control, 20, 0x7ff)
BUILD_TRB_RW(sia, control, 31, 0x1)

static inline u64 trb_read_data_ptr(struct tegra_xudc_trb *trb)
{
	return ((u64)trb_read_data_hi(trb) << 32) |
		trb_read_data_lo(trb);
}

static inline void trb_write_data_ptr(struct tegra_xudc_trb *trb, u64 addr)
{
	trb_write_data_lo(trb, lower_32_bits(addr));
	trb_write_data_hi(trb, upper_32_bits(addr));
}

struct tegra_xudc_request {
	struct usb_request usb_req;

	size_t buf_queued;
	unsigned int trbs_queued;
	unsigned int trbs_needed;
	bool need_zlp;

	struct tegra_xudc_trb *first_trb;
	struct tegra_xudc_trb *last_trb;

	struct list_head list;
};

struct tegra_xudc_ep {
	struct tegra_xudc *xudc;
	struct usb_ep usb_ep;
	unsigned int index;
	char name[8];

	struct tegra_xudc_ep_context *context;

#define XUDC_TRANSFER_RING_SIZE 64
	struct tegra_xudc_trb *transfer_ring;
	dma_addr_t transfer_ring_phys;

	unsigned int enq_ptr;
	unsigned int deq_ptr;
	bool pcs;
	bool ring_full;
	bool stream_rejected;

	struct list_head queue;
	const struct usb_endpoint_descriptor *desc;
	const struct usb_ss_ep_comp_descriptor *comp_desc;
};

struct tegra_xudc_sel_timing {
	__u8 u1sel;
	__u8 u1pel;
	__le16 u2sel;
	__le16 u2pel;
};

enum tegra_xudc_setup_state {
	WAIT_FOR_SETUP,
	DATA_STAGE_XFER,
	DATA_STAGE_RECV,
	STATUS_STAGE_XFER,
	STATUS_STAGE_RECV,
};

struct tegra_xudc_setup_packet {
	struct usb_ctrlrequest ctrl_req;
	unsigned int seq_num;
};

struct tegra_xudc_save_regs {
	u32 ctrl;
	u32 portpm;
};

struct tegra_xudc {
	struct device *dev;
	const struct tegra_xudc_soc_data *soc;
	struct tegra_xusb_padctl *padctl;

	spinlock_t lock;

	struct usb_gadget gadget;
	struct usb_gadget_driver *driver;

#define XUDC_NR_EVENT_RINGS 2
#define XUDC_EVENT_RING_SIZE 4096
	struct tegra_xudc_trb *event_ring[XUDC_NR_EVENT_RINGS];
	dma_addr_t event_ring_phys[XUDC_NR_EVENT_RINGS];
	unsigned int event_ring_index;
	unsigned int event_ring_deq_ptr;
	bool ccs;

#define XUDC_NR_EPS 32
	struct tegra_xudc_ep ep[XUDC_NR_EPS];
	struct tegra_xudc_ep_context *ep_context;
	dma_addr_t ep_context_phys;

	struct dma_pool *transfer_ring_pool;

	bool queued_setup_packet;
	struct tegra_xudc_setup_packet setup_packet;
	enum tegra_xudc_setup_state setup_state;
	u16 setup_seq_num;

	u16 dev_addr;
	u16 isoch_delay;
	struct tegra_xudc_sel_timing sel_timing;
	u8 test_mode_pattern;
	u16 status_buf;
	struct tegra_xudc_request *ep0_req;

	bool pullup;

	unsigned int nr_enabled_eps;
	unsigned int nr_isoch_eps;

	unsigned int device_state;
	unsigned int resume_state;

	int irq;

	void __iomem *base;
	resource_size_t phys_base;
	void __iomem *ipfs;
	void __iomem *fpci;

	struct regulator_bulk_data *supplies;

	struct clk **clks;
	int num_clks;
	bool clk_enabled;

	bool device_mode;
	int device_active; /* 1-based */
	int dev_mode_num;

	struct extcon_dev *data_role_extcons[XUSB_MAX_OTG_PORT_NUM];

	struct notifier_block data_role_nb;
	struct work_struct data_role_work;

	struct phy *utmi_phy[XUSB_MAX_OTG_PORT_NUM];
	struct phy *usb3_phy[XUSB_MAX_OTG_PORT_NUM];

	struct tegra_xudc_save_regs saved_regs;
	bool suspended;
	bool powergated;

	struct completion disconnect_complete;

	/* charger detection */
	struct tegra_usb_cd *ucd;
	unsigned int connect_type;
#define NON_STD_CHARGER_DET_TIME_MS 2000
#define USB_ANDROID_SUSPEND_CURRENT_MA 2
	struct work_struct set_charging_current_work;
	struct delayed_work non_std_charger_work;
	u32 current_ma;
	bool selfpowered;

	struct tegra_bwmgr_client *bwmgr;
	struct work_struct boost_emc;
	unsigned long last_boosted;
	struct delayed_work restore_emc;
	u32 emc_frequency_required;
	bool emc_frequency_boosted;
	bool restore_work_scheduled;

#define TOGGLE_VBUS_WAIT_MS 100
	struct delayed_work plc_reset_work;
	bool wait_csc;

	struct pm_qos_request core_req;
	struct pm_qos_request boost_cpufreq_req;
	struct work_struct	boost_cpufreq_work;
	unsigned int boost_cpu_freq;
	unsigned long cpufreq_last_boosted;
	bool cpu_boost_enabled;
	bool cpu_boost_work_scheduled;

	struct delayed_work port_reset_war_work;
	bool wait_for_sec_prc;

	struct work_struct pullup_work;
};

#define XUDC_TRB_MAX_BUFFER_SIZE 65536
#define XUDC_MAX_ISOCH_EPS 4
#define XUDC_INTERRUPT_MODERATION_US 0

static struct usb_endpoint_descriptor tegra_xudc_ep0_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = 0,
	.bmAttributes = USB_ENDPOINT_XFER_CONTROL,
	.wMaxPacketSize = cpu_to_le16(64),
};

struct tegra_xudc_soc_data {
	u16 device_id;
	const char * const *supply_names;
	unsigned int num_supplies;
	bool u1_enable;
	bool u2_enable;
	bool lpm_enable;
	bool invalid_seq_num;
	bool pls_quirk;
	bool disable_elpg;
	bool port_reset_quirk;
	bool port_speed_quirk;
};

static bool u1_enable;
module_param(u1_enable, bool, 0644);

static bool u2_enable;
module_param(u2_enable, bool, 0644);

static bool lpm_enable;
module_param(lpm_enable, bool, 0644);

static bool vbus_wakelock = true;
static DEFINE_SPINLOCK(wl_spinlock);
struct vbus_lock {
	struct wakeup_source wakelock;
	bool held;
};
static struct vbus_lock lock;

static inline u32 fpci_readl(struct tegra_xudc *xudc, u32 addr)
{
	return readl(xudc->fpci + addr);
}

static inline void fpci_writel(struct tegra_xudc *xudc, u32 val, u32 addr)
{
	writel(val, xudc->fpci + addr);
}

static inline u32 ipfs_readl(struct tegra_xudc *xudc, u32 addr)
{
	return readl(xudc->ipfs + addr);
}

static inline void ipfs_writel(struct tegra_xudc *xudc, u32 val, u32 addr)
{
	writel(val, xudc->ipfs + addr);
}

static inline u32 xudc_readl(struct tegra_xudc *xudc, u32 addr)
{
	return readl(xudc->base + addr);
}

static inline void xudc_writel(struct tegra_xudc *xudc, u32 val, u32 addr)
{
	writel(val, xudc->base + addr);
}

static inline int xudc_readl_poll(struct tegra_xudc *xudc, u32 addr, u32 mask,
				  u32 val)
{
	u32 regval;

	return readl_poll_timeout_atomic(xudc->base + addr, regval,
					 (regval & mask) == val, 1, 100);
}

static inline struct tegra_xudc *to_xudc(struct usb_gadget *gadget)
{
	return container_of(gadget, struct tegra_xudc, gadget);
}

static inline struct tegra_xudc_ep *to_xudc_ep(struct usb_ep *ep)
{
	return container_of(ep, struct tegra_xudc_ep, usb_ep);
}

static inline struct tegra_xudc_request *to_xudc_req(struct usb_request *req)
{
	return container_of(req, struct tegra_xudc_request, usb_req);
}

static inline void dump_trb(struct tegra_xudc *xudc, const char *type,
			    struct tegra_xudc_trb *trb)
{
	dev_dbg(xudc->dev,
		"%s: %p, lo = %#x, hi = %#x, status = %#x, control = %#x\n",
		type, trb, trb->data_lo, trb->data_hi, trb->status,
		trb->control);
}

static void tegra_fpga_hack_init(struct tegra_xudc *xudc)
{
	dev_info(xudc->dev, "setup mods values\n");
	xudc_writel(xudc, 0x9C, 0x100);
	xudc_writel(xudc, 0x1ADD, 0x104);
	xudc_writel(xudc, 0x1871, 0x108);
	xudc_writel(xudc, 0x1E848, 0x10c);
	xudc_writel(xudc, 0x9c4, 0x110);
	xudc_writel(xudc, 0xEA6, 0x114);
	xudc_writel(xudc, 0x2DCB7, 0x118);
	xudc_writel(xudc, 0x74, 0x11c);
	xudc_writel(xudc, 0x5b, 0x120);
	xudc_writel(xudc, 0x98968, 0x124);
	xudc_writel(xudc, 0x1E87, 0x128);
	xudc_writel(xudc, 0xF444, 0x12c);
	xudc_writel(xudc, 0x1FE, 0x130);
	xudc_writel(xudc, 0xC35, 0x134);
	xudc_writel(xudc, 0x21, 0x18c);
	xudc_writel(xudc, 0x5b, 0x190);
	xudc_writel(xudc, 0x0, 0x19c);
}

static void tegra_xudc_limit_port_speed(struct tegra_xudc *xudc)
{
	u32 val;

	/* limit port speed to gen 1 */
	val = xudc_readl(xudc, SSPX_CORE_CNT56);
	val &= ~(SSPX_CORE_CNT56_SCD_BIT0_TRPT_MAX_MASK <<
		 SSPX_CORE_CNT56_SCD_BIT0_TRPT_MAX_SHIFT);
	val |= 0x260 << SSPX_CORE_CNT56_SCD_BIT0_TRPT_MAX_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT56);

	val = xudc_readl(xudc, SSPX_CORE_CNT57);
	val &= ~(SSPX_CORE_CNT57_SCD_BIT1_TRPT_MAX_MASK <<
		 SSPX_CORE_CNT57_SCD_BIT1_TRPT_MAX_SHIFT);
	val |= 0x6D6 << SSPX_CORE_CNT57_SCD_BIT1_TRPT_MAX_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT57);

	val = xudc_readl(xudc, SSPX_CORE_CNT65);
	val &= ~(SSPX_CORE_CNT65_TX_SCD_END_TRPT_MID_MASK <<
		 SSPX_CORE_CNT65_TX_SCD_END_TRPT_MID_SHIFT);
	val |= 0x4B0 << SSPX_CORE_CNT65_TX_SCD_END_TRPT_MID_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT66);

	val = xudc_readl(xudc, SSPX_CORE_CNT66);
	val &= ~(SSPX_CORE_CNT66_TX_SCD_BIT0_TRPT_MID_MASK <<
		 SSPX_CORE_CNT66_TX_SCD_BIT0_TRPT_MID_SHIFT);
	val |= 0x4B0 << SSPX_CORE_CNT66_TX_SCD_BIT0_TRPT_MID_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT66);

	val = xudc_readl(xudc, SSPX_CORE_CNT67);
	val &= ~(SSPX_CORE_CNT67_TX_SCD_BIT1_TRPT_MID_MASK <<
		 SSPX_CORE_CNT67_TX_SCD_BIT1_TRPT_MID_SHIFT);
	val |= 0x4B0 << SSPX_CORE_CNT67_TX_SCD_BIT1_TRPT_MID_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT67);

	val = xudc_readl(xudc, SSPX_CORE_CNT72);
	val &= ~(SSPX_CORE_CNT72_SCD_LFPS_TIMEOUT_MASK <<
		 SSPX_CORE_CNT72_SCD_LFPS_TIMEOUT_SHIFT);
	val |= 0x10 << SSPX_CORE_CNT72_SCD_LFPS_TIMEOUT_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT72);
}

static void tegra_xudc_restore_port_speed(struct tegra_xudc *xudc)
{
	u32 val;

	/* restore port speed to gen2 */
	val = xudc_readl(xudc, SSPX_CORE_CNT56);
	val &= ~(SSPX_CORE_CNT56_SCD_BIT0_TRPT_MAX_MASK <<
		 SSPX_CORE_CNT56_SCD_BIT0_TRPT_MAX_SHIFT);
	val |= 0x438 << SSPX_CORE_CNT56_SCD_BIT0_TRPT_MAX_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT56);

	val = xudc_readl(xudc, SSPX_CORE_CNT57);
	val &= ~(SSPX_CORE_CNT57_SCD_BIT1_TRPT_MAX_MASK <<
		 SSPX_CORE_CNT57_SCD_BIT1_TRPT_MAX_SHIFT);
	val |= 0x528 << SSPX_CORE_CNT57_SCD_BIT1_TRPT_MAX_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT57);

	val = xudc_readl(xudc, SSPX_CORE_CNT65);
	val &= ~(SSPX_CORE_CNT65_TX_SCD_END_TRPT_MID_MASK <<
		 SSPX_CORE_CNT65_TX_SCD_END_TRPT_MID_SHIFT);
	val |= 0xE10 << SSPX_CORE_CNT65_TX_SCD_END_TRPT_MID_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT66);

	val = xudc_readl(xudc, SSPX_CORE_CNT66);
	val &= ~(SSPX_CORE_CNT66_TX_SCD_BIT0_TRPT_MID_MASK <<
		 SSPX_CORE_CNT66_TX_SCD_BIT0_TRPT_MID_SHIFT);
	val |= 0x348 << SSPX_CORE_CNT66_TX_SCD_BIT0_TRPT_MID_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT66);

	val = xudc_readl(xudc, SSPX_CORE_CNT67);
	val &= ~(SSPX_CORE_CNT67_TX_SCD_BIT1_TRPT_MID_MASK <<
		 SSPX_CORE_CNT67_TX_SCD_BIT1_TRPT_MID_SHIFT);
	val |= 0x5a0 << SSPX_CORE_CNT67_TX_SCD_BIT1_TRPT_MID_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT67);

	val = xudc_readl(xudc, SSPX_CORE_CNT72);
	val &= ~(SSPX_CORE_CNT72_SCD_LFPS_TIMEOUT_MASK <<
		 SSPX_CORE_CNT72_SCD_LFPS_TIMEOUT_SHIFT);
	val |= 0x1c21 << SSPX_CORE_CNT72_SCD_LFPS_TIMEOUT_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT72);

}

static void vbus_hold_wl(struct vbus_lock *lock)
{
	if (!lock->held) {
		__pm_stay_awake(&lock->wakelock);
		lock->held = true;
		pr_debug("[hold VBUS wakelock]\n");
	}
}

#define TEMPORARY_WAKELOCK_HOLD_TIME	2000
static void vbus_hold_temp_wl(struct vbus_lock *lock)
{
	__pm_wakeup_event(&lock->wakelock, TEMPORARY_WAKELOCK_HOLD_TIME);
	lock->held = false;
	pr_debug("[hold temporary VBUS wakelock for %d ms]\n",
			TEMPORARY_WAKELOCK_HOLD_TIME);
}

static void vbus_drop_wl(struct vbus_lock *lock)
{
	if (lock->held) {
		__pm_relax(&lock->wakelock);
		lock->held = false;
		pr_debug("[drop VBUS wakelock]\n");
	}
}

static void tegra_xudc_update_wakelock(struct tegra_xudc *xudc)
{
	unsigned long flags;

	if (!vbus_wakelock)
		return;

	spin_lock_irqsave(&wl_spinlock, flags);

	switch (xudc->connect_type) {
	case EXTCON_USB:
	case EXTCON_CHG_USB_CDP:
		vbus_hold_wl(&lock);
		break;
	case EXTCON_NONE:
		vbus_drop_wl(&lock);
		break;
	default:
		vbus_hold_temp_wl(&lock);
	};

	spin_unlock_irqrestore(&wl_spinlock, flags);
}

static void tegra_xudc_device_mode_on(struct tegra_xudc *xudc, int i)
{
	unsigned long flags;
	unsigned int type;
	int err;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->device_mode) {
		spin_unlock_irqrestore(&xudc->lock, flags);
		return;
	}
	spin_unlock_irqrestore(&xudc->lock, flags);

	/* charger detection should be done when b_idle->b_peripheral only */
	if (xudc->ucd && !xudc->gadget.is_a_peripheral) {
		type = tegra_ucd_detect_cable_and_set_current(xudc->ucd);

		spin_lock_irqsave(&xudc->lock, flags);
		xudc->connect_type = type;
		if (xudc->connect_type == EXTCON_USB && xudc->pullup)
			schedule_delayed_work(&xudc->non_std_charger_work,
				msecs_to_jiffies(NON_STD_CHARGER_DET_TIME_MS));
		spin_unlock_irqrestore(&xudc->lock, flags);
	}

	tegra_xudc_update_wakelock(xudc);

	pm_runtime_get_sync(xudc->dev);

	tegra_xusb_padctl_set_vbus_override_early(xudc->padctl, i);

	err = phy_power_on(xudc->utmi_phy[i]);
	if (err < 0)
		dev_err(xudc->dev, "utmi power on failed %d @ %d\n", err, i);
	err = phy_power_on(xudc->usb3_phy[i]);
	if (err < 0)
		dev_err(xudc->dev, "usb3 phy power on failed %d @ %d\n", err,
			i);

	spin_lock_irqsave(&xudc->lock, flags);
	dev_info(xudc->dev, "device mode on: %d\n", i);

	tegra_xusb_padctl_set_vbus_override(xudc->padctl, i);

	xudc->device_mode = true;
	spin_unlock_irqrestore(&xudc->lock, flags);

	if (xudc->utmi_phy[i])
		tegra_phy_xusb_utmi_pad_power_on(xudc->utmi_phy[i]);
}

static void tegra_xudc_device_mode_off(struct tegra_xudc *xudc, int i)
{
	bool connected = false;
	unsigned long flags;
	u32 pls, val;
	int err;

	spin_lock_irqsave(&xudc->lock, flags);
	if (!xudc->device_mode) {
		spin_unlock_irqrestore(&xudc->lock, flags);
		return;
	}

	dev_info(xudc->dev, "device mode off: %d\n", i);

	if (xudc->ucd) {
		cancel_delayed_work(&xudc->non_std_charger_work);
		xudc->current_ma = 0;
	}

	connected = !!(xudc_readl(xudc, PORTSC) & PORTSC_CCS);
	reinit_completion(&xudc->disconnect_complete);

	if (xudc->soc->port_speed_quirk)
		tegra_xudc_restore_port_speed(xudc);

	tegra_xusb_padctl_clear_vbus_override(xudc->padctl, i);

	pls = (xudc_readl(xudc, PORTSC) >> PORTSC_PLS_SHIFT) &
		PORTSC_PLS_MASK;

	/* Direct link to U0 if disconnected in RESUME or U2. */
	if (xudc->soc->pls_quirk && xudc->gadget.speed == USB_SPEED_SUPER &&
	    (pls == PORTSC_PLS_RESUME || pls == PORTSC_PLS_U2)) {
		val = xudc_readl(xudc, PORTPM);
		val |= PORTPM_FRWE;
		xudc_writel(xudc, val, PORTPM);

		val = xudc_readl(xudc, PORTSC);
		val &= ~(PORTSC_CHANGE_MASK |
			 (PORTSC_PLS_MASK << PORTSC_PLS_SHIFT));
		val |= PORTSC_LWS | (PORTSC_PLS_U0 << PORTSC_PLS_SHIFT);
		xudc_writel(xudc, val, PORTSC);
	}

	xudc->device_mode = false;
	spin_unlock_irqrestore(&xudc->lock, flags);

	if (xudc->utmi_phy[i])
		tegra_phy_xusb_utmi_pad_power_down(xudc->utmi_phy[i]);

	/* Wait for disconnect event. */
	if (connected)
		wait_for_completion(&xudc->disconnect_complete);

	/* Make sure interrupt handler has completed before powergating. */
	synchronize_irq(xudc->irq);

	err = phy_power_off(xudc->utmi_phy[i]);
	if (err < 0)
		dev_err(xudc->dev, "utmi_phy power off failed %d @ %d\n", err,
			i);
	err = phy_power_off(xudc->usb3_phy[i]);
	if (err < 0)
		dev_err(xudc->dev, "usb3_phy power off failed %d @ %d\n", err,
			i);

	if (xudc->ucd)
		tegra_ucd_set_charger_type(xudc->ucd, EXTCON_NONE);

	tegra_xudc_update_wakelock(xudc);

	pm_runtime_put(xudc->dev);
}

static void tegra_xudc_update_data_role(struct tegra_xudc *xudc, int i)
{
	struct extcon_dev *edev;

	if (tegra_platform_is_fpga()) {
		tegra_xudc_device_mode_on(xudc, i);
		return;
	}

	edev = xudc->data_role_extcons[i];

	if (extcon_get_cable_state_(edev, EXTCON_USB)) {
		xudc->connect_type = EXTCON_USB;
		tegra_xudc_device_mode_on(xudc, i);
		xudc->device_active = i + 1;
	} else {
		xudc->connect_type = EXTCON_NONE;
		tegra_xudc_device_mode_off(xudc, i);
		xudc->device_active = 0;
	}
}

static void tegra_xudc_update_extcon(struct tegra_xudc *xudc);
static void tegra_xudc_data_role_work(struct work_struct *work)
{
	struct tegra_xudc *xudc = container_of(work, struct tegra_xudc,
					       data_role_work);

	tegra_xudc_update_extcon(xudc);
}

static void tegra_xudc_boost_emc_work(struct work_struct *work)
{
	struct tegra_xudc *xudc = container_of(work, struct tegra_xudc,
						boost_emc);
	unsigned long flags;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->bwmgr && !xudc->emc_frequency_boosted) {
		spin_unlock_irqrestore(&xudc->lock, flags);
		tegra_bwmgr_set_emc(xudc->bwmgr, xudc->emc_frequency_required,
				TEGRA_BWMGR_SET_EMC_SHARED_BW);
		dev_dbg(xudc->dev, "Requesting emc bw to %d\n",
						xudc->emc_frequency_required);
		spin_lock_irqsave(&xudc->lock, flags);
		xudc->emc_frequency_boosted = true;
	}

	if (!xudc->restore_work_scheduled) {
		schedule_delayed_work(&xudc->restore_emc, EMC_RESTORE_DELAY);
		xudc->restore_work_scheduled = true;
	}
	xudc->last_boosted = jiffies;
	spin_unlock_irqrestore(&xudc->lock, flags);
}

static void tegra_xudc_restore_emc_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct tegra_xudc *xudc = container_of(dwork, struct tegra_xudc,
						restore_emc);
	unsigned long flags;

	if (time_is_after_jiffies(xudc->last_boosted + EMC_RESTORE_DELAY)) {
		dev_dbg(xudc->dev, "schedule restore emc work\n");
		schedule_delayed_work(&xudc->restore_emc, EMC_RESTORE_DELAY);
		return;
	}

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->bwmgr && xudc->emc_frequency_boosted) {
		spin_unlock_irqrestore(&xudc->lock, flags);
		tegra_bwmgr_set_emc(xudc->bwmgr, 0,
				TEGRA_BWMGR_SET_EMC_SHARED_BW);
		dev_dbg(xudc->dev, "Restoring emc bw\n");
		spin_lock_irqsave(&xudc->lock, flags);
		xudc->emc_frequency_boosted = false;
		xudc->restore_work_scheduled = false;
	}
	spin_unlock_irqrestore(&xudc->lock, flags);
}

static void tegra_xudc_boost_cpufreq_fn(struct work_struct *work)
{
	struct tegra_xudc *xudc = container_of(work, struct tegra_xudc,
						boost_cpufreq_work);
	unsigned long delay = CPU_BOOST_TIMEOUT;
	s32 cpu_freq = xudc->boost_cpu_freq * 1000;

	dev_dbg(xudc->dev, "Boost CPU freq %d KHz, with timeout %lu ms\n",
						cpu_freq, delay);

	if (XUDC_IS_T210(xudc))
		pm_qos_update_request_timeout(&xudc->core_req,
			cpu_freq, delay * 1000);
	pm_qos_update_request_timeout(&xudc->boost_cpufreq_req,
		cpu_freq, delay * 1000);

	xudc->cpufreq_last_boosted = jiffies;
	xudc->cpu_boost_work_scheduled = false;
}

static void tegra_xudc_boost_cpu_init(struct tegra_xudc *xudc)
{
	INIT_WORK(&xudc->boost_cpufreq_work, tegra_xudc_boost_cpufreq_fn);

	if (XUDC_IS_T210(xudc))
		pm_qos_add_request(&xudc->core_req, PM_QOS_MIN_ONLINE_CPUS,
							PM_QOS_DEFAULT_VALUE);
	pm_qos_add_request(&xudc->boost_cpufreq_req,
		PM_QOS_CPU_FREQ_MIN, PM_QOS_DEFAULT_VALUE);
	xudc->cpufreq_last_boosted = jiffies;
	xudc->cpu_boost_work_scheduled = false;
}

static void tegra_xudc_boost_cpu_deinit(struct tegra_xudc *xudc)
{
	cancel_work_sync(&xudc->boost_cpufreq_work);

	if (XUDC_IS_T210(xudc))
		pm_qos_remove_request(&xudc->core_req);
	pm_qos_remove_request(&xudc->boost_cpufreq_req);
}

static int tegra_xudc_data_role_notifier(struct notifier_block *nb,
					 unsigned long event, void *unused)
{
	struct tegra_xudc *xudc = container_of(nb, struct tegra_xudc,
					       data_role_nb);
	unsigned long flags;

	if (tegra_platform_is_fpga())
		return NOTIFY_DONE;

	spin_lock_irqsave(&xudc->lock, flags);
	if (!xudc->suspended)
		schedule_work(&xudc->data_role_work);
	spin_unlock_irqrestore(&xudc->lock, flags);

	return NOTIFY_DONE;
}

static void tegra_xudc_plc_reset_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct tegra_xudc *xudc = container_of(dwork, struct tegra_xudc,
					       plc_reset_work);
	unsigned long flags;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->wait_csc) {
		u32 pls = (xudc_readl(xudc, PORTSC) >> PORTSC_PLS_SHIFT) &
			  PORTSC_PLS_MASK;
		if (pls == PORTSC_PLS_INACTIVE) {
			int vbus_id = xudc->device_active - 1;

			dev_info(xudc->dev, "PLS = Inactive. Toggle VBUS\n");
			tegra_xusb_padctl_clear_vbus_override(xudc->padctl,
					vbus_id);
			tegra_xusb_padctl_set_vbus_override(xudc->padctl,
					vbus_id);
			xudc->wait_csc = false;
		}
	}
	spin_unlock_irqrestore(&xudc->lock, flags);
}

static void tegra_xudc_port_reset_war_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct tegra_xudc *xudc =
		container_of(dwork, struct tegra_xudc, port_reset_war_work);
	unsigned long flags;
	u32 pls;
	int ret;

	if (xudc->utmi_phy[0] == NULL)
		return;

	dev_info(xudc->dev, "port_reset_war_work\n");
	spin_lock_irqsave(&xudc->lock, flags);
	if (extcon_get_cable_state_(xudc->data_role_extcons[0], EXTCON_USB) &&
						xudc->wait_for_sec_prc) {
		pls = (xudc_readl(xudc, PORTSC) >> PORTSC_PLS_SHIFT) &
			PORTSC_PLS_MASK;
		dev_info(xudc->dev, "pls = %x\n", pls);

		if (pls == PORTSC_PLS_DISABLED) {
			dev_info(xudc->dev, "toggle vbus\n");
			/* PRC doesn't complete in 100ms, toggle the vbus */
			ret =
			tegra_phy_xusb_utmi_port_reset_quirk(xudc->utmi_phy[0]);
			if (ret == 1)
				xudc->wait_for_sec_prc = 0;
		}
	}

	spin_unlock_irqrestore(&xudc->lock, flags);
}

static dma_addr_t trb_virt_to_phys(struct tegra_xudc_ep *ep,
				   struct tegra_xudc_trb *trb)
{
	unsigned int index;
	dma_addr_t phys;

	index = trb - ep->transfer_ring;
	if (WARN_ON(index >= XUDC_TRANSFER_RING_SIZE))
		return 0;
	phys = ep->transfer_ring_phys + index * sizeof(*trb);

	return phys;
}

static struct tegra_xudc_trb *trb_phys_to_virt(struct tegra_xudc_ep *ep,
					       dma_addr_t addr)
{
	struct tegra_xudc_trb *trb;
	unsigned int index;

	index = (addr - ep->transfer_ring_phys) / sizeof(*trb);
	if (WARN_ON(index >= XUDC_TRANSFER_RING_SIZE))
		return NULL;
	trb = &ep->transfer_ring[index];

	return trb;
}

static void ep_reload(struct tegra_xudc *xudc, unsigned int ep)
{
	xudc_writel(xudc, BIT(ep), EP_RELOAD);
	xudc_readl_poll(xudc, EP_RELOAD, BIT(ep), 0);
}

static void ep_pause(struct tegra_xudc *xudc, unsigned int ep)
{
	u32 val;

	val = xudc_readl(xudc, EP_PAUSE);
	if (val & BIT(ep))
		return;
	val |= BIT(ep);
	xudc_writel(xudc, val, EP_PAUSE);

	xudc_readl_poll(xudc, EP_STCHG, BIT(ep), BIT(ep));

	xudc_writel(xudc, BIT(ep), EP_STCHG);
}

static void ep_unpause(struct tegra_xudc *xudc, unsigned int ep)
{
	u32 val;

	val = xudc_readl(xudc, EP_PAUSE);
	if (!(val & BIT(ep)))
		return;
	val &= ~BIT(ep);
	xudc_writel(xudc, val, EP_PAUSE);

	xudc_readl_poll(xudc, EP_STCHG, BIT(ep), BIT(ep));

	xudc_writel(xudc, BIT(ep), EP_STCHG);
}

static void ep_unpause_all(struct tegra_xudc *xudc)
{
	u32 val;

	val = xudc_readl(xudc, EP_PAUSE);
	xudc_writel(xudc, 0, EP_PAUSE);

	xudc_readl_poll(xudc, EP_STCHG, val, val);

	xudc_writel(xudc, val, EP_STCHG);
}

static void ep_halt(struct tegra_xudc *xudc, unsigned int ep)
{
	u32 val;

	val = xudc_readl(xudc, EP_HALT);
	if (val & BIT(ep))
		return;
	val |= BIT(ep);
	xudc_writel(xudc, val, EP_HALT);

	xudc_readl_poll(xudc, EP_STCHG, BIT(ep), BIT(ep));

	xudc_writel(xudc, BIT(ep), EP_STCHG);
}

static void ep_unhalt(struct tegra_xudc *xudc, unsigned int ep)
{
	u32 val;

	val = xudc_readl(xudc, EP_HALT);
	if (!(val & BIT(ep)))
		return;
	val &= ~BIT(ep);
	xudc_writel(xudc, val, EP_HALT);

	xudc_readl_poll(xudc, EP_STCHG, BIT(ep), BIT(ep));

	xudc_writel(xudc, BIT(ep), EP_STCHG);
}

static void ep_unhalt_all(struct tegra_xudc *xudc)
{
	u32 val;

	val = xudc_readl(xudc, EP_HALT);
	if (!val)
		return;
	xudc_writel(xudc, 0, EP_HALT);

	xudc_readl_poll(xudc, EP_STCHG, val, val);

	xudc_writel(xudc, val, EP_STCHG);
}

static void ep_wait_for_stopped(struct tegra_xudc *xudc, unsigned int ep)
{
	xudc_readl_poll(xudc, EP_STOPPED, BIT(ep), BIT(ep));
	xudc_writel(xudc, BIT(ep), EP_STOPPED);
}

static void ep_wait_for_inactive(struct tegra_xudc *xudc, unsigned int ep)
{
	xudc_readl_poll(xudc, EP_THREAD_ACTIVE, BIT(ep), 0);
}

static void tegra_xudc_req_done(struct tegra_xudc_ep *ep,
				struct tegra_xudc_request *req, int status)
{
	struct tegra_xudc *xudc = ep->xudc;

	dev_dbg(xudc->dev, "completing request %p on ep %u with status %d\n",
		 req, ep->index, status);

	if (likely(req->usb_req.status == -EINPROGRESS))
		req->usb_req.status = status;

	list_del_init(&req->list);

	if (usb_endpoint_xfer_control(ep->desc)) {
		usb_gadget_unmap_request(&xudc->gadget, &req->usb_req,
					 (xudc->setup_state ==
					  DATA_STAGE_XFER));
	} else {
		usb_gadget_unmap_request(&xudc->gadget, &req->usb_req,
					 usb_endpoint_dir_in(ep->desc));
	}

	spin_unlock(&xudc->lock);
	usb_gadget_giveback_request(&ep->usb_ep, &req->usb_req);
	spin_lock(&xudc->lock);
}

static void tegra_xudc_ep_nuke(struct tegra_xudc_ep *ep, int status)
{
	struct tegra_xudc_request *req;

	while (!list_empty(&ep->queue)) {
		req = list_first_entry(&ep->queue, struct tegra_xudc_request,
				       list);
		tegra_xudc_req_done(ep, req, status);
	}
}

static unsigned int ep_available_trbs(struct tegra_xudc_ep *ep)
{
	if (ep->ring_full)
		return 0;
	if (ep->deq_ptr > ep->enq_ptr)
		return ep->deq_ptr - ep->enq_ptr - 1;
	return XUDC_TRANSFER_RING_SIZE - (ep->enq_ptr - ep->deq_ptr) - 2;
}

static void tegra_xudc_queue_one_trb(struct tegra_xudc_ep *ep,
				     struct tegra_xudc_request *req,
				     struct tegra_xudc_trb *trb,
				     bool ioc)
{
	struct tegra_xudc *xudc = ep->xudc;
	dma_addr_t buf_addr;
	size_t len;

	len = min_t(size_t, XUDC_TRB_MAX_BUFFER_SIZE, req->usb_req.length -
		    req->buf_queued);
	if (len > 0)
		buf_addr = req->usb_req.dma + req->buf_queued;
	else
		buf_addr = 0;

	trb_write_data_ptr(trb, buf_addr);

	trb_write_transfer_len(trb, len);
	trb_write_td_size(trb, req->trbs_needed - req->trbs_queued - 1);

	if (req->trbs_queued == req->trbs_needed - 1 ||
		(req->need_zlp && req->trbs_queued == req->trbs_needed - 2))
		trb_write_chain(trb, 0);
	else
		trb_write_chain(trb, 1);
	trb_write_ioc(trb, ioc);

	if (usb_endpoint_dir_out(ep->desc) ||
	    (usb_endpoint_xfer_control(ep->desc) &&
	     (xudc->setup_state == DATA_STAGE_RECV)))
		trb_write_isp(trb, 1);
	else
		trb_write_isp(trb, 0);

	if (usb_endpoint_xfer_control(ep->desc)) {
		if (xudc->setup_state == DATA_STAGE_XFER ||
		    xudc->setup_state == DATA_STAGE_RECV)
			trb_write_type(trb, TRB_TYPE_DATA_STAGE);
		else
			trb_write_type(trb, TRB_TYPE_STATUS_STAGE);
		if (xudc->setup_state == DATA_STAGE_XFER ||
		    xudc->setup_state == STATUS_STAGE_XFER)
			trb_write_data_stage_dir(trb, 1);
		else
			trb_write_data_stage_dir(trb, 0);
	} else if (usb_endpoint_xfer_isoc(ep->desc)) {
		trb_write_type(trb, TRB_TYPE_ISOCH);
		trb_write_sia(trb, 1);
		trb_write_frame_id(trb, 0);
		trb_write_tlbpc(trb, 0);
	} else if (usb_ss_max_streams(ep->comp_desc)) {
		trb_write_type(trb, TRB_TYPE_STREAM);
		trb_write_stream_id(trb, req->usb_req.stream_id);
	} else {
		trb_write_type(trb, TRB_TYPE_NORMAL);
		trb_write_stream_id(trb, 0);
	}

	trb_write_cycle(trb, ep->pcs);

	req->trbs_queued++;
	req->buf_queued += len;

	dump_trb(xudc, "TRANSFER", trb);
}

static unsigned int tegra_xudc_queue_trbs(struct tegra_xudc_ep *ep,
					  struct tegra_xudc_request *req)
{
	unsigned int i, count, available;
	bool wait_td = false;

	available = ep_available_trbs(ep);
	count = req->trbs_needed - req->trbs_queued;
	if (available < count) {
		count = available;
		ep->ring_full = true;
	}

	/*
	 * To generate zero-length packet on USB bus, SW needs schedule a
	 * standalone zero-length TD. According to HW's behavior, SW needs
	 * to schedule TDs in different ways for different endpoint types.
	 *
	 * For control endpoint:
	 * - Data stage TD (IOC = 1, CH = 0)
	 * - Ring doorbell and wait transfer event
	 * - Data stage TD for ZLP (IOC = 1, CH = 0)
	 * - Ring doorbell
	 *
	 * For bulk and interrupt endpoints:
	 * - Normal transfer TD (IOC = 0, CH = 0)
	 * - Normal transfer TD for ZLP (IOC = 1, CH = 0)
	 * - Ring doorbell
	 */

	if (req->need_zlp && usb_endpoint_xfer_control(ep->desc) && count > 1)
		wait_td = true;

	if (!req->first_trb)
		req->first_trb = &ep->transfer_ring[ep->enq_ptr];

	for (i = 0; i < count; i++) {
		struct tegra_xudc_trb *trb = &ep->transfer_ring[ep->enq_ptr];
		bool ioc = false;

		if ((i == count - 1) || (wait_td && i == count - 2))
			ioc = true;

		tegra_xudc_queue_one_trb(ep, req, trb, ioc);
		req->last_trb = trb;

		ep->enq_ptr++;
		if (ep->enq_ptr == XUDC_TRANSFER_RING_SIZE - 1) {
			trb = &ep->transfer_ring[ep->enq_ptr];
			trb_write_cycle(trb, ep->pcs);
			ep->pcs = !ep->pcs;
			ep->enq_ptr = 0;
		}

		if (ioc)
			break;
	}

	return count;
}

static void tegra_xudc_ep_ring_doorbell(struct tegra_xudc_ep *ep)
{
	struct tegra_xudc *xudc = ep->xudc;
	u32 val;

	if (list_empty(&ep->queue))
		return;

	val = ep->index << DB_TARGET_SHIFT;
	if (usb_endpoint_xfer_control(ep->desc)) {
		val |= xudc->setup_seq_num << DB_STREAMID_SHIFT;
	} else if (usb_ss_max_streams(ep->comp_desc) > 0) {
		struct tegra_xudc_request *req;

		/* Don't ring doorbell if the stream has been rejected. */
		if (ep->stream_rejected)
			return;
		req = list_first_entry(&ep->queue, struct tegra_xudc_request,
				       list);
		val |= req->usb_req.stream_id << DB_STREAMID_SHIFT;
	}
	dev_dbg(xudc->dev, "ring doorbell: %#x\n", val);
	xudc_writel(xudc, val, DB);
}

static void tegra_xudc_ep_kick_queue(struct tegra_xudc_ep *ep)
{
	struct tegra_xudc_request *req;
	bool trbs_queued = false;

	list_for_each_entry(req, &ep->queue, list) {
		if (ep->ring_full)
			break;
		if (tegra_xudc_queue_trbs(ep, req) > 0)
			trbs_queued = true;
	}

	if (trbs_queued)
		tegra_xudc_ep_ring_doorbell(ep);
}

static int
__tegra_xudc_ep_queue(struct tegra_xudc_ep *ep, struct tegra_xudc_request *req)
{
	struct tegra_xudc *xudc = ep->xudc;
	int err;
	bool skip_cpu_boost = false;

	if (usb_endpoint_xfer_control(ep->desc) && !list_empty(&ep->queue)) {
		dev_err(xudc->dev, "control ep has pending transfers\n");
		return -EINVAL;
	}

	if (usb_endpoint_xfer_control(ep->desc)) {
		err = usb_gadget_map_request(&xudc->gadget, &req->usb_req,
					     (xudc->setup_state ==
					      DATA_STAGE_XFER));
	} else {
		err = usb_gadget_map_request(&xudc->gadget, &req->usb_req,
					     usb_endpoint_dir_in(ep->desc));
	}
	if (err < 0) {
		dev_err(xudc->dev, "failed to map request: %d\n", err);
		return err;
	}

	req->first_trb = NULL;
	req->last_trb = NULL;
	req->buf_queued = 0;
	req->trbs_queued = 0;
	req->need_zlp = false;
	req->trbs_needed = DIV_ROUND_UP(req->usb_req.length,
					XUDC_TRB_MAX_BUFFER_SIZE);
	if (req->usb_req.length == 0)
		req->trbs_needed++;
	if (!usb_endpoint_xfer_isoc(ep->desc) &&
	    req->usb_req.zero && (req->usb_req.length != 0) &&
	    ((req->usb_req.length % ep->usb_ep.maxpacket) == 0)) {
		req->trbs_needed++;
		req->need_zlp = true;
	}

	req->usb_req.status = -EINPROGRESS;
	req->usb_req.actual = 0;

	if (req->usb_req.length >= BOOST_TRIGGER) {
		if (xudc->bwmgr)
			schedule_work(&xudc->boost_emc);
		if (time_is_after_jiffies(xudc->cpufreq_last_boosted
			       + (msecs_to_jiffies(CPU_BOOST_TIMEOUT / 2))))
			skip_cpu_boost = true;
		if (xudc->cpu_boost_enabled && !skip_cpu_boost &&
					!xudc->cpu_boost_work_scheduled) {
			dev_dbg(xudc->dev, "Scheduling cpu boost work\n");
			schedule_work(&xudc->boost_cpufreq_work);
			xudc->cpu_boost_work_scheduled = true;
		}
	}

	list_add_tail(&req->list, &ep->queue);

	tegra_xudc_ep_kick_queue(ep);

	return 0;
}

static int
tegra_xudc_ep_queue(struct usb_ep *usb_ep, struct usb_request *usb_req,
		    gfp_t gfp)
{
	struct tegra_xudc_request *req;
	struct tegra_xudc_ep *ep;
	struct tegra_xudc *xudc;
	unsigned long flags;
	int ret;

	if (!usb_ep || !usb_req)
		return -EINVAL;
	ep = to_xudc_ep(usb_ep);
	req = to_xudc_req(usb_req);
	xudc = ep->xudc;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->powergated || !ep->desc) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	ret = __tegra_xudc_ep_queue(ep, req);
unlock:
	spin_unlock_irqrestore(&xudc->lock, flags);

	return ret;
}

static void squeeze_transfer_ring(struct tegra_xudc_ep *ep,
				  struct tegra_xudc_request *req)
{
	struct tegra_xudc_trb *trb = req->first_trb;
	bool pcs_enq = trb_read_cycle(trb);
	bool pcs;


	/*
	 * Clear out all the TRBs part of or after the cancelled request,
	 * and must correct trb cycle bit to the last un-enqueued state.
	 */
	while (trb != &ep->transfer_ring[ep->enq_ptr]) {
		pcs = trb_read_cycle(trb);
		memset(trb, 0, sizeof(*trb));
		trb_write_cycle(trb, !pcs);
		trb++;

		if (trb_read_type(trb) == TRB_TYPE_LINK)
			trb = ep->transfer_ring;
	}

	/* Requests will be re-queued at the start of the cancelled request. */
	ep->enq_ptr = req->first_trb - ep->transfer_ring;
	/*
	 * Retrieve the correct cycle bit state from the first trb of
	 * the cancelled request.
	 */
	ep->pcs = pcs_enq;
	ep->ring_full = false;
	list_for_each_entry_continue(req, &ep->queue, list) {
		req->usb_req.status = -EINPROGRESS;
		req->usb_req.actual = 0;

		req->first_trb = NULL;
		req->last_trb = NULL;
		req->buf_queued = 0;
		req->trbs_queued = 0;
	}
}

/*
 * Determine if the given TRB is in the range [first trb, last trb] for the
 * given request.
 */
static bool trb_in_request(struct tegra_xudc_ep *ep,
			   struct tegra_xudc_request *req,
			   struct tegra_xudc_trb *trb)
{
	dev_dbg(ep->xudc->dev, "%s: request %p -> %p; trb %p\n", __func__,
		req->first_trb, req->last_trb, trb);

	if (trb >= req->first_trb && (trb <= req->last_trb ||
				      req->last_trb < req->first_trb))
		return true;
	if (trb < req->first_trb && trb <= req->last_trb &&
	    req->last_trb < req->first_trb)
		return true;
	return false;
}

/*
 * Determine if the given TRB is in the range [EP enqueue pointer, first TRB)
 * for the given endpoint and request.
 */
static bool trb_before_request(struct tegra_xudc_ep *ep,
			       struct tegra_xudc_request *req,
			       struct tegra_xudc_trb *trb)
{
	struct tegra_xudc_trb *enq_trb = &ep->transfer_ring[ep->enq_ptr];

	dev_dbg(ep->xudc->dev, "%s: request %p -> %p; enq ptr: %p; trb %p\n",
		__func__, req->first_trb, req->last_trb, enq_trb, trb);

	if (trb < req->first_trb && (enq_trb <= trb ||
				     req->first_trb < enq_trb))
		return true;
	if (trb > req->first_trb && req->first_trb < enq_trb && enq_trb <= trb)
		return true;
	return false;
}

static int
__tegra_xudc_ep_dequeue(struct tegra_xudc_ep *ep,
			struct tegra_xudc_request *req)
{
	struct tegra_xudc *xudc = ep->xudc;
	struct tegra_xudc_request *r;
	struct tegra_xudc_trb *deq_trb;
	bool busy, kick_queue = false;
	int ret = 0;

	/* Make sure the request is actually queued to this endpoint. */
	list_for_each_entry(r, &ep->queue, list) {
		if (r == req)
			break;
	}
	if (r != req)
		return -EINVAL;

	/* Request hasn't been queued in the transfer ring yet. */
	if (!req->trbs_queued) {
		tegra_xudc_req_done(ep, req, -ECONNRESET);
		return 0;
	}

	/* Halt DMA for this endpiont. */
	if (ep_ctx_read_state(ep->context) == EP_STATE_RUNNING) {
		ep_pause(xudc, ep->index);
		ep_wait_for_inactive(xudc, ep->index);
	}

	deq_trb = trb_phys_to_virt(ep, ep_ctx_read_deq_ptr(ep->context));
	/* Is the hardware processing the TRB at the dequeue pointer? */
	busy = (trb_read_cycle(deq_trb) == ep_ctx_read_dcs(ep->context));

	if (trb_in_request(ep, req, deq_trb) && busy) {
		/*
		 * Request has been partially completed or it hasn't
		 * started processing yet.
		 */
		dma_addr_t deq_ptr;

		squeeze_transfer_ring(ep, req);

		req->usb_req.actual = ep_ctx_read_edtla(ep->context);
		tegra_xudc_req_done(ep, req, -ECONNRESET);
		kick_queue = true;

		/* EDTLA is > 0: request has been partially completed */
		if (req->usb_req.actual > 0) {
			/*
			 * Abort the pending transfer and update the dequeue
			 * pointer
			 */
			ep_ctx_write_edtla(ep->context, 0);
			ep_ctx_write_partial_td(ep->context, 0);
			ep_ctx_write_data_offset(ep->context, 0);

			deq_ptr = trb_virt_to_phys(ep,
					&ep->transfer_ring[ep->enq_ptr]);
			ep_ctx_write_deq_ptr(ep->context, deq_ptr);
			ep_ctx_write_dcs(ep->context, ep->pcs);

			ep_reload(xudc, ep->index);
		}
	} else if (trb_before_request(ep, req, deq_trb) && busy) {
		/* Request hasn't started processing yet. */
		squeeze_transfer_ring(ep, req);

		tegra_xudc_req_done(ep, req, -ECONNRESET);
		kick_queue = true;
	} else {
		/*
		 * Request has completed, but we haven't processed the
		 * completion event yet.
		 */
		tegra_xudc_req_done(ep, req, -ECONNRESET);
		ret = -EINVAL;
	}

	/* Resume the endpoint. */
	ep_unpause(xudc, ep->index);

	if (kick_queue)
		tegra_xudc_ep_kick_queue(ep);

	return ret;
}

static int
tegra_xudc_ep_dequeue(struct usb_ep *usb_ep, struct usb_request *usb_req)
{
	struct tegra_xudc_request *req;
	struct tegra_xudc_ep *ep;
	struct tegra_xudc *xudc;
	unsigned long flags;
	int ret;

	if (!usb_ep || !usb_req)
		return -EINVAL;
	ep = to_xudc_ep(usb_ep);
	req = to_xudc_req(usb_req);
	xudc = ep->xudc;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->powergated || !ep->desc) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	ret = __tegra_xudc_ep_dequeue(ep, req);
unlock:
	spin_unlock_irqrestore(&xudc->lock, flags);

	return ret;
}

static int __tegra_xudc_ep_set_halt(struct tegra_xudc_ep *ep, bool halt)
{
	struct tegra_xudc *xudc = ep->xudc;

	if (!ep->desc)
		return -EINVAL;

	if (usb_endpoint_xfer_isoc(ep->desc)) {
		dev_err(xudc->dev, "can't halt iscoh ep\n");
		return -ENOTSUPP;
	}

	if (!!(xudc_readl(xudc, EP_HALT) & BIT(ep->index)) == halt) {
		dev_dbg(xudc->dev, "ep %u already %s\n", ep->index,
			halt ? "halted" : "not halted");
		return 0;
	}

	if (halt) {
		ep_halt(xudc, ep->index);
	} else {
		ep_ctx_write_state(ep->context, EP_STATE_DISABLED);

		ep_reload(xudc, ep->index);

		ep_ctx_write_state(ep->context, EP_STATE_RUNNING);

		ep_ctx_write_rsvd(ep->context, 0);
		ep_ctx_write_partial_td(ep->context, 0);
		ep_ctx_write_splitxstate(ep->context, 0);
		ep_ctx_write_seq_num(ep->context, 0);

		ep_reload(xudc, ep->index);
		ep_unpause(xudc, ep->index);
		ep_unhalt(xudc, ep->index);

		tegra_xudc_ep_ring_doorbell(ep);
	}

	return 0;
}

static int tegra_xudc_ep_set_halt(struct usb_ep *usb_ep, int value)
{
	struct tegra_xudc_ep *ep;
	struct tegra_xudc *xudc;
	unsigned long flags;
	int ret;

	if (!usb_ep)
		return -EINVAL;

	ep = to_xudc_ep(usb_ep);
	xudc = ep->xudc;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->powergated) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	if (value && usb_endpoint_dir_in(ep->desc) &&
	    !list_empty(&ep->queue)) {
		dev_err(xudc->dev, "can't halt ep with requests pending\n");
		ret = -EAGAIN;
		goto unlock;
	}
	ret = __tegra_xudc_ep_set_halt(ep, value);
unlock:
	spin_unlock_irqrestore(&xudc->lock, flags);

	return ret;
}

static void tegra_xudc_ep_context_setup(struct tegra_xudc_ep *ep)
{
	const struct usb_endpoint_descriptor *desc = ep->desc;
	const struct usb_ss_ep_comp_descriptor *comp_desc = ep->comp_desc;
	struct tegra_xudc *xudc = ep->xudc;
	u16 maxpacket, maxburst = 0, esit = 0;
	u32 val;

	maxpacket = usb_endpoint_maxp(desc) & 0x7ff;
	if (xudc->gadget.speed == USB_SPEED_SUPER) {
		if (!usb_endpoint_xfer_control(desc))
			maxburst = comp_desc->bMaxBurst;
		if (usb_endpoint_xfer_int(desc) || usb_endpoint_xfer_isoc(desc))
			esit = le16_to_cpu(comp_desc->wBytesPerInterval);
	} else if ((xudc->gadget.speed < USB_SPEED_SUPER) &&
		   (usb_endpoint_xfer_int(desc) ||
		    usb_endpoint_xfer_isoc(desc))) {
		if (xudc->gadget.speed == USB_SPEED_HIGH) {
			maxburst = (usb_endpoint_maxp(desc) >> 11) & 0x3;
			if (maxburst == 0x3) {
				dev_warn(xudc->dev,
					 "invalid endpoint maxburst\n");
				maxburst = 0x2;
			}
		}
		esit = maxpacket * (maxburst + 1);
	}

	memset(ep->context, 0, sizeof(*ep->context));

	ep_ctx_write_state(ep->context, EP_STATE_RUNNING);
	ep_ctx_write_interval(ep->context, desc->bInterval);
	if (xudc->gadget.speed == USB_SPEED_SUPER) {
		if (usb_endpoint_xfer_isoc(desc)) {
			ep_ctx_write_mult(ep->context,
					  comp_desc->bmAttributes & 0x3);
		}
		if (usb_endpoint_xfer_bulk(desc)) {
			ep_ctx_write_max_pstreams(ep->context,
						  comp_desc->bmAttributes &
						  0x1f);
			ep_ctx_write_lsa(ep->context, 1);
		}
	}

	if (!usb_endpoint_xfer_control(desc) && usb_endpoint_dir_out(desc))
		val = usb_endpoint_type(desc);
	else
		val = usb_endpoint_type(desc) + EP_TYPE_CONTROL;
	ep_ctx_write_type(ep->context, val);
	ep_ctx_write_cerr(ep->context, 0x3);
	ep_ctx_write_max_packet_size(ep->context, maxpacket);
	ep_ctx_write_max_burst_size(ep->context, maxburst);

	ep_ctx_write_deq_ptr(ep->context, ep->transfer_ring_phys);
	ep_ctx_write_dcs(ep->context, ep->pcs);

	/* Select a reasonable average TRB length based on endpoint type. */
	switch (usb_endpoint_type(desc)) {
	case USB_ENDPOINT_XFER_CONTROL:
		val = 8;
		break;
	case USB_ENDPOINT_XFER_INT:
		val = 1024;
		break;
	case USB_ENDPOINT_XFER_BULK:
	case USB_ENDPOINT_XFER_ISOC:
	default:
		val = 3072;
		break;
	}
	ep_ctx_write_avg_trb_len(ep->context, val);
	ep_ctx_write_max_esit_payload(ep->context, esit);

	ep_ctx_write_cerrcnt(ep->context, 0x3);
}

static void setup_link_trb(struct tegra_xudc_ep *ep,
			   struct tegra_xudc_trb *trb)
{
	trb_write_data_ptr(trb, ep->transfer_ring_phys);
	trb_write_type(trb, TRB_TYPE_LINK);
	trb_write_toggle_cycle(trb, 1);
}

static int __tegra_xudc_ep_disable(struct tegra_xudc_ep *ep)
{
	struct tegra_xudc *xudc = ep->xudc;

	if (ep_ctx_read_state(ep->context) == EP_STATE_DISABLED) {
		dev_err(xudc->dev, "endpoint %u already disabled\n",
			ep->index);
		return -EINVAL;
	}
	ep_ctx_write_state(ep->context, EP_STATE_DISABLED);

	ep_reload(xudc, ep->index);

	tegra_xudc_ep_nuke(ep, -ESHUTDOWN);

	xudc->nr_enabled_eps--;
	if (usb_endpoint_xfer_isoc(ep->desc))
		xudc->nr_isoch_eps--;

	ep->desc = NULL;
	ep->comp_desc = NULL;

	memset(ep->context, 0, sizeof(*ep->context));

	ep_unpause(xudc, ep->index);
	ep_unhalt(xudc, ep->index);
	if (xudc_readl(xudc, EP_STOPPED) & BIT(ep->index))
		xudc_writel(xudc, BIT(ep->index), EP_STOPPED);

	/*
	 * If this is the last endpoint disabled in a de-configure request,
	 * switch back to address state.
	 */
	if ((xudc->device_state == USB_STATE_CONFIGURED) &&
	    (xudc->nr_enabled_eps == 1)) {
		u32 val;

		xudc->device_state = USB_STATE_ADDRESS;
		usb_gadget_set_state(&xudc->gadget, xudc->device_state);

		val = xudc_readl(xudc, CTRL);
		val &= ~CTRL_RUN;
		xudc_writel(xudc, val, CTRL);
	}

	dev_info(xudc->dev, "ep %u disabled\n", ep->index);

	return 0;
}

static int tegra_xudc_ep_disable(struct usb_ep *usb_ep)
{
	struct tegra_xudc_ep *ep;
	struct tegra_xudc *xudc;
	unsigned long flags;
	int ret;

	if (!usb_ep)
		return -EINVAL;

	ep = to_xudc_ep(usb_ep);
	xudc = ep->xudc;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->powergated) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	ret = __tegra_xudc_ep_disable(ep);
unlock:
	spin_unlock_irqrestore(&xudc->lock, flags);

	return ret;
}

static int __tegra_xudc_ep_enable(struct tegra_xudc_ep *ep,
				  const struct usb_endpoint_descriptor *desc)
{
	struct tegra_xudc *xudc = ep->xudc;
	unsigned int i;
	u32 val;

	if (xudc->gadget.speed == USB_SPEED_SUPER &&
		!usb_endpoint_xfer_control(desc) && !ep->usb_ep.comp_desc)
		return -EINVAL;

	/* Disable the EP if it is not disabled */
	if (ep_ctx_read_state(ep->context) != EP_STATE_DISABLED)
		__tegra_xudc_ep_disable(ep);

	ep->desc = desc;
	ep->comp_desc = ep->usb_ep.comp_desc;

	if (usb_endpoint_xfer_isoc(desc)) {
		if (xudc->nr_isoch_eps > XUDC_MAX_ISOCH_EPS) {
			dev_err(xudc->dev, "too many isoch endpoints\n");
			return -EBUSY;
		}
		xudc->nr_isoch_eps++;
	}

	memset(ep->transfer_ring, 0, XUDC_TRANSFER_RING_SIZE *
	       sizeof(*ep->transfer_ring));
	setup_link_trb(ep, &ep->transfer_ring[XUDC_TRANSFER_RING_SIZE - 1]);

	ep->enq_ptr = 0;
	ep->deq_ptr = 0;
	ep->pcs = true;
	ep->ring_full = false;
	xudc->nr_enabled_eps++;

	tegra_xudc_ep_context_setup(ep);

	/*
	 * No need to reload and un-halt EP0.  This will be done automatically
	 * once a valid SETUP packet is received.
	 */
	if (usb_endpoint_xfer_control(desc))
		goto out;

	/*
	 * Transition to configured state once the first non-control
	 * endpoint is enabled.
	 */
	if (xudc->device_state == USB_STATE_ADDRESS) {
		val = xudc_readl(xudc, CTRL);
		val |= CTRL_RUN;
		xudc_writel(xudc, val, CTRL);

		xudc->device_state = USB_STATE_CONFIGURED;
		usb_gadget_set_state(&xudc->gadget, xudc->device_state);
	}

	if (usb_endpoint_xfer_isoc(desc)) {
		/*
		 * Pause all bulk endpoints when enabling an isoch endpoint
		 * to ensure the isoch endpoint is allocated enough bandwidth.
		 */
		for (i = 0; i < ARRAY_SIZE(xudc->ep); i++) {
			if (xudc->ep[i].desc &&
			    usb_endpoint_xfer_bulk(xudc->ep[i].desc))
				ep_pause(xudc, i);
		}
	}

	ep_reload(xudc, ep->index);
	ep_unpause(xudc, ep->index);
	ep_unhalt(xudc, ep->index);

	if (usb_endpoint_xfer_isoc(desc)) {
		for (i = 0; i < ARRAY_SIZE(xudc->ep); i++) {
			if (xudc->ep[i].desc &&
			    usb_endpoint_xfer_bulk(xudc->ep[i].desc))
				ep_unpause(xudc, i);
		}
	}

out:
	dev_info(xudc->dev, "ep %u (type: %d, dir: %s) enabled\n", ep->index,
		 usb_endpoint_type(ep->desc),
		 usb_endpoint_dir_in(ep->desc) ? "in" : "out");

	return 0;
}

static int tegra_xudc_ep_enable(struct usb_ep *usb_ep,
				const struct usb_endpoint_descriptor *desc)
{
	struct tegra_xudc_ep *ep;
	struct tegra_xudc *xudc;
	unsigned long flags;
	int ret;

	if  (!usb_ep || !desc || (desc->bDescriptorType != USB_DT_ENDPOINT))
		return -EINVAL;

	ep = to_xudc_ep(usb_ep);
	xudc = ep->xudc;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->powergated) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	ret = __tegra_xudc_ep_enable(ep, desc);
unlock:
	spin_unlock_irqrestore(&xudc->lock, flags);

	return ret;
}

static struct usb_request *
tegra_xudc_ep_alloc_request(struct usb_ep *usb_ep, gfp_t gfp)
{
	struct tegra_xudc_request *req;

	req = kzalloc(sizeof(*req), gfp);
	if (!req)
		return NULL;

	INIT_LIST_HEAD(&req->list);

	return &req->usb_req;
}

static void tegra_xudc_ep_free_request(struct usb_ep *usb_ep,
				       struct usb_request *usb_req)
{
	struct tegra_xudc_request *req = to_xudc_req(usb_req);

	kfree(req);
}

static struct usb_ep_ops tegra_xudc_ep_ops = {
	.enable = tegra_xudc_ep_enable,
	.disable = tegra_xudc_ep_disable,
	.alloc_request = tegra_xudc_ep_alloc_request,
	.free_request = tegra_xudc_ep_free_request,
	.queue = tegra_xudc_ep_queue,
	.dequeue = tegra_xudc_ep_dequeue,
	.set_halt = tegra_xudc_ep_set_halt,
};

static int tegra_xudc_ep0_enable(struct usb_ep *usb_ep,
				 const struct usb_endpoint_descriptor *desc)
{
	return -EINVAL;
}

static int tegra_xudc_ep0_disable(struct usb_ep *usb_ep)
{
	return -EINVAL;
}

static struct usb_ep_ops tegra_xudc_ep0_ops = {
	.enable = tegra_xudc_ep0_enable,
	.disable = tegra_xudc_ep0_disable,
	.alloc_request = tegra_xudc_ep_alloc_request,
	.free_request = tegra_xudc_ep_free_request,
	.queue = tegra_xudc_ep_queue,
	.dequeue = tegra_xudc_ep_dequeue,
	.set_halt = tegra_xudc_ep_set_halt,
};

static int tegra_xudc_gadget_get_frame(struct usb_gadget *gadget)
{
	struct tegra_xudc *xudc = to_xudc(gadget);
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->powergated) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	ret = (xudc_readl(xudc, MFINDEX) >> MFINDEX_FRAME_SHIFT) &
		MFINDEX_FRAME_MASK;
unlock:
	spin_unlock_irqrestore(&xudc->lock, flags);

	return ret;
}

static void tegra_xudc_resume_device_state(struct tegra_xudc *xudc)
{
	unsigned int i;
	u32 val;

	ep_unpause_all(xudc);

	/* Direct link to U0. */
	val = xudc_readl(xudc, PORTSC);
	if (((val >> PORTSC_PLS_SHIFT) & PORTSC_PLS_MASK) != PORTSC_PLS_U0) {
		val &= ~(PORTSC_CHANGE_MASK |
			 (PORTSC_PLS_MASK << PORTSC_PLS_SHIFT));
		val |= PORTSC_LWS | (PORTSC_PLS_U0 << PORTSC_PLS_SHIFT);
		xudc_writel(xudc, val, PORTSC);
	}

	if (xudc->device_state == USB_STATE_SUSPENDED) {
		xudc->device_state = xudc->resume_state;
		usb_gadget_set_state(&xudc->gadget, xudc->device_state);
		xudc->resume_state = 0;
	}

	/*
	 * Doorbells may be dropped if they are sent too soon (< ~200ns)
	 * after unpausing the endpoint.  Wait for 500ns just to be safe.
	 */
	ndelay(500);
	for (i = 0; i < ARRAY_SIZE(xudc->ep); i++)
		tegra_xudc_ep_ring_doorbell(&xudc->ep[i]);
}

static int tegra_xudc_gadget_wakeup(struct usb_gadget *gadget)
{
	struct tegra_xudc *xudc = to_xudc(gadget);
	unsigned long flags;
	int ret = 0;
	u32 val;

	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->powergated) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	val = xudc_readl(xudc, PORTPM);
	dev_dbg(xudc->dev, "%s: PORTPM=%#x, speed=%x\n", __func__,
			val, gadget->speed);
	if (((xudc->gadget.speed <= USB_SPEED_HIGH) &&
	     (val & PORTPM_RWE)) ||
	    ((xudc->gadget.speed == USB_SPEED_SUPER) &&
	     (val & PORTPM_FRWE))) {
		tegra_xudc_resume_device_state(xudc);

		/* Send Device Notification packet. */
		if (xudc->gadget.speed == USB_SPEED_SUPER) {
			val = (DEVNOTIF_LO_TYPE_FUNCTION_WAKE <<
			       DEVNOTIF_LO_TYPE_SHIFT) | DEVNOTIF_LO_TRIG;
			xudc_writel(xudc, 0, DEVNOTIF_HI);
			xudc_writel(xudc, val, DEVNOTIF_LO);
		}
	}
unlock:
	spin_unlock_irqrestore(&xudc->lock, flags);

	return ret;
}

static void tegra_xudc_gadget_pullup_work(struct work_struct *work)
{
	struct tegra_xudc *xudc = container_of(work, struct tegra_xudc,
						pullup_work);
	unsigned long flags;
	u32 val;

	pm_runtime_get_sync(xudc->dev);
	spin_lock_irqsave(&xudc->lock, flags);
	val = xudc_readl(xudc, CTRL);
	if (xudc->pullup)
		val |= CTRL_ENABLE;
	else
		val &= ~CTRL_ENABLE;
	xudc_writel(xudc, val, CTRL);
	if (xudc->ucd && xudc->device_mode &&
	    xudc->connect_type == EXTCON_USB && xudc->pullup)
		schedule_delayed_work(&xudc->non_std_charger_work,
			msecs_to_jiffies(NON_STD_CHARGER_DET_TIME_MS));
	spin_unlock_irqrestore(&xudc->lock, flags);
	pm_runtime_put(xudc->dev);

}

static int tegra_xudc_gadget_pullup(struct usb_gadget *gadget, int is_on)
{
	struct tegra_xudc *xudc = to_xudc(gadget);
	unsigned long flags;

	spin_lock_irqsave(&xudc->lock, flags);
	if (is_on != xudc->pullup) {
		xudc->pullup = is_on;
		schedule_work(&xudc->pullup_work);
	}
	spin_unlock_irqrestore(&xudc->lock, flags);

	return 0;
}

static int tegra_xudc_gadget_start(struct usb_gadget *gadget,
				   struct usb_gadget_driver *driver)
{
	struct tegra_xudc *xudc = to_xudc(gadget);
	unsigned long flags;
	u32 val;
	int ret;

	if (!driver)
		return -EINVAL;

	dev_dbg(xudc->dev, "%s\n", __func__);

	pm_runtime_get_sync(xudc->dev);
	cancel_work_sync(&xudc->pullup_work);
	spin_lock_irqsave(&xudc->lock, flags);
	if (xudc->driver) {
		ret = -EBUSY;
		goto unlock;
	}

	xudc->setup_state = WAIT_FOR_SETUP;
	xudc->device_state = USB_STATE_DEFAULT;
	usb_gadget_set_state(&xudc->gadget, xudc->device_state);

	ret = __tegra_xudc_ep_enable(&xudc->ep[0], &tegra_xudc_ep0_desc);
	if (ret < 0)
		goto unlock;

	val = xudc_readl(xudc, CTRL);
	val |= CTRL_IE | CTRL_LSE;
	xudc_writel(xudc, val, CTRL);

	val = xudc_readl(xudc, PORTHALT);
	val |= PORTHALT_STCHG_INTR_EN;
	xudc_writel(xudc, val, PORTHALT);

	if (xudc->pullup) {
		val = xudc_readl(xudc, CTRL);
		val |= CTRL_ENABLE;
		xudc_writel(xudc, val, CTRL);
	}

	xudc->driver = driver;
unlock:
	spin_unlock_irqrestore(&xudc->lock, flags);
	pm_runtime_put(xudc->dev);
	dev_dbg(xudc->dev, "%s done\n", __func__);
	return ret;
}

static int tegra_xudc_gadget_stop(struct usb_gadget *gadget)
{
	struct tegra_xudc *xudc = to_xudc(gadget);
	unsigned long flags;
	u32 val;

	pm_runtime_get_sync(xudc->dev);
	cancel_work_sync(&xudc->pullup_work);
	spin_lock_irqsave(&xudc->lock, flags);
	val = xudc_readl(xudc, CTRL);
	val &= ~(CTRL_IE | CTRL_ENABLE);
	xudc_writel(xudc, val, CTRL);

	__tegra_xudc_ep_disable(&xudc->ep[0]);

	xudc->driver = NULL;
	spin_unlock_irqrestore(&xudc->lock, flags);
	pm_runtime_put(xudc->dev);

	return 0;
}

static void tegra_xudc_set_charging_current_work(struct work_struct *work)
{
	struct tegra_xudc *xudc = container_of(work, struct tegra_xudc,
				  set_charging_current_work);

	dev_dbg(xudc->dev, "%s\n", __func__);
	tegra_ucd_set_sdp_cdp_current(xudc->ucd, xudc->current_ma);
}

static int tegra_xudc_gadget_vbus_draw(struct usb_gadget *gadget,
						unsigned int m_a)
{
	struct tegra_xudc *xudc = to_xudc(gadget);

	dev_dbg(xudc->dev, "%s: %u mA\n", __func__, m_a);

	if (xudc->ucd && xudc->current_ma != m_a) {
		xudc->current_ma = m_a;
		schedule_work(&xudc->set_charging_current_work);
	}

	return 0;
}

static int tegra_xudc_set_selfpowered(struct usb_gadget *gadget, int is_on)
{
	struct tegra_xudc *xudc = to_xudc(gadget);

	dev_dbg(xudc->dev, "%s: %d\n", __func__, is_on);
	xudc->selfpowered = !!is_on;

	return 0;
}

static struct usb_gadget_ops tegra_xudc_gadget_ops = {
	.get_frame = tegra_xudc_gadget_get_frame,
	.wakeup = tegra_xudc_gadget_wakeup,
	.pullup = tegra_xudc_gadget_pullup,
	.udc_start = tegra_xudc_gadget_start,
	.udc_stop = tegra_xudc_gadget_stop,
	.vbus_draw = tegra_xudc_gadget_vbus_draw,
	.set_selfpowered = tegra_xudc_set_selfpowered,
};

static void no_op_complete(struct usb_ep *ep, struct usb_request *req)
{
}

static int
tegra_xudc_ep0_queue_status(struct tegra_xudc *xudc,
		void (*cmpl)(struct usb_ep *, struct usb_request *))
{
	xudc->ep0_req->usb_req.buf = NULL;
	xudc->ep0_req->usb_req.dma = 0;
	xudc->ep0_req->usb_req.length = 0;
	xudc->ep0_req->usb_req.complete = cmpl;
	xudc->ep0_req->usb_req.context = xudc;

	return __tegra_xudc_ep_queue(&xudc->ep[0], xudc->ep0_req);
}

static int
tegra_xudc_ep0_queue_data(struct tegra_xudc *xudc, void *buf, size_t len,
		void (*cmpl)(struct usb_ep *, struct usb_request *))
{
	xudc->ep0_req->usb_req.buf = buf;
	xudc->ep0_req->usb_req.length = len;
	xudc->ep0_req->usb_req.complete = cmpl;
	xudc->ep0_req->usb_req.context = xudc;

	return __tegra_xudc_ep_queue(&xudc->ep[0], xudc->ep0_req);
}

static void tegra_xudc_ep0_req_done(struct tegra_xudc *xudc)
{
	switch (xudc->setup_state) {
	case DATA_STAGE_XFER:
		xudc->setup_state = STATUS_STAGE_RECV;
		tegra_xudc_ep0_queue_status(xudc, no_op_complete);
		break;
	case DATA_STAGE_RECV:
		xudc->setup_state = STATUS_STAGE_XFER;
		tegra_xudc_ep0_queue_status(xudc, no_op_complete);
		break;
	default:
		xudc->setup_state = WAIT_FOR_SETUP;
		break;
	}
}

static int tegra_xudc_ep0_delegate_req(struct tegra_xudc *xudc,
				       struct usb_ctrlrequest *ctrl)
{
	int ret;

	spin_unlock(&xudc->lock);
	ret = xudc->driver->setup(&xudc->gadget, ctrl);
	spin_lock(&xudc->lock);

	return ret;
}

static void set_feature_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct tegra_xudc *xudc = req->context;

	if (xudc->test_mode_pattern) {
		xudc_writel(xudc, xudc->test_mode_pattern, PORT_TM);
		xudc->test_mode_pattern = 0;
	}
}

static int tegra_xudc_ep0_set_feature(struct tegra_xudc *xudc,
				      struct usb_ctrlrequest *ctrl)
{
	bool set = (ctrl->bRequest == USB_REQ_SET_FEATURE);
	u32 feature = le16_to_cpu(ctrl->wValue);
	u32 index = le16_to_cpu(ctrl->wIndex);
	u32 val, ep;
	int ret;

	if (le16_to_cpu(ctrl->wLength) != 0)
		return -EINVAL;

	switch (ctrl->bRequestType & USB_RECIP_MASK) {
	case USB_RECIP_DEVICE:
		switch (feature) {
		case USB_DEVICE_REMOTE_WAKEUP:
			if ((xudc->gadget.speed == USB_SPEED_SUPER) ||
			    (xudc->device_state == USB_STATE_DEFAULT))
				return -EINVAL;

			val = xudc_readl(xudc, PORTPM);
			if (set)
				val |= PORTPM_RWE;
			else
				val &= ~PORTPM_RWE;
			xudc_writel(xudc, val, PORTPM);
			break;
		case USB_DEVICE_U1_ENABLE:
		case USB_DEVICE_U2_ENABLE:
			if ((xudc->device_state != USB_STATE_CONFIGURED) ||
			    (xudc->gadget.speed != USB_SPEED_SUPER))
				return -EINVAL;

			val = xudc_readl(xudc, PORTPM);
			if ((feature == USB_DEVICE_U1_ENABLE) && u1_enable) {
				if (set)
					val |= PORTPM_U1E;
				else
					val &= ~PORTPM_U1E;
			}
			if ((feature == USB_DEVICE_U2_ENABLE) && u2_enable) {
				if (set)
					val |= PORTPM_U2E;
				else
					val &= ~PORTPM_U2E;
			}
			xudc_writel(xudc, val, PORTPM);
			break;
		case USB_DEVICE_TEST_MODE:
			if (xudc->gadget.speed != USB_SPEED_HIGH)
				return -EINVAL;
			if (!set)
				return -EINVAL;

			xudc->test_mode_pattern = index >> 8;
			break;
		default:
			return -EINVAL;
		}

		break;
	case USB_RECIP_INTERFACE:
		if (xudc->device_state != USB_STATE_CONFIGURED)
			return -EINVAL;

		switch (feature) {
		case USB_INTRF_FUNC_SUSPEND:
			if (set) {
				val = xudc_readl(xudc, PORTPM);
				if (index & USB_INTRF_FUNC_SUSPEND_RW)
					val |= PORTPM_FRWE;
				else
					val &= ~PORTPM_FRWE;
				xudc_writel(xudc, val, PORTPM);
			}
			return tegra_xudc_ep0_delegate_req(xudc, ctrl);
		default:
			return -EINVAL;
		}

		break;
	case USB_RECIP_ENDPOINT:
		ep = (index & USB_ENDPOINT_NUMBER_MASK) * 2 +
			((index & USB_DIR_IN) ? 1 : 0);

		if ((xudc->device_state == USB_STATE_DEFAULT) ||
		    ((xudc->device_state == USB_STATE_ADDRESS) &&
		     (index != 0)))
			return -EINVAL;

		ret = __tegra_xudc_ep_set_halt(&xudc->ep[ep], set);
		if (ret < 0)
			return ret;
		break;
	default:
		return -EINVAL;
	}

	return tegra_xudc_ep0_queue_status(xudc, set_feature_complete);
}

static int tegra_xudc_ep0_get_status(struct tegra_xudc *xudc,
				     struct usb_ctrlrequest *ctrl)
{
	struct tegra_xudc_ep_context *ep_ctx;
	u32 val, ep, index = le16_to_cpu(ctrl->wIndex);
	u16 status = 0;

	if (!(ctrl->bRequestType & USB_DIR_IN))
		return -EINVAL;

	if ((le16_to_cpu(ctrl->wValue) != 0) ||
	    (le16_to_cpu(ctrl->wLength) != 2))
		return -EINVAL;

	switch (ctrl->bRequestType & USB_RECIP_MASK) {
	case USB_RECIP_DEVICE:
		val = xudc_readl(xudc, PORTPM);

		if (xudc->selfpowered)
			status |= BIT(USB_DEVICE_SELF_POWERED);

		if ((xudc->gadget.speed < USB_SPEED_SUPER) &&
		    (val & PORTPM_RWE))
			status |= BIT(USB_DEVICE_REMOTE_WAKEUP);

		if (xudc->gadget.speed == USB_SPEED_SUPER) {
			if (val & PORTPM_U1E)
				status |= BIT(USB_DEV_STAT_U1_ENABLED);
			if (val & PORTPM_U2E)
				status |= BIT(USB_DEV_STAT_U2_ENABLED);
		}
		break;
	case USB_RECIP_INTERFACE:
		if (xudc->gadget.speed == USB_SPEED_SUPER) {
			status |= USB_INTRF_STAT_FUNC_RW_CAP;
			val = xudc_readl(xudc, PORTPM);
			if (val & PORTPM_FRWE)
				status |= USB_INTRF_STAT_FUNC_RW;
		}
		break;
	case USB_RECIP_ENDPOINT:
		ep = (index & USB_ENDPOINT_NUMBER_MASK) * 2 +
			((index & USB_DIR_IN) ? 1 : 0);
		ep_ctx = &xudc->ep_context[ep];

		if ((xudc->device_state != USB_STATE_CONFIGURED) &&
		    ((xudc->device_state != USB_STATE_ADDRESS) || (ep != 0)))
			return -EINVAL;

		if (ep_ctx_read_state(ep_ctx) == EP_STATE_DISABLED)
			return -EINVAL;

		if (xudc_readl(xudc, EP_HALT) & BIT(ep))
			status |= BIT(USB_ENDPOINT_HALT);
		break;
	default:
		return -EINVAL;
	}

	xudc->status_buf = cpu_to_le16(status);
	return tegra_xudc_ep0_queue_data(xudc, &xudc->status_buf,
					 sizeof(xudc->status_buf),
					 no_op_complete);
}

static void set_sel_complete(struct usb_ep *ep, struct usb_request *req)
{
	/* Nothing to do with SEL values */
}

static int tegra_xudc_ep0_set_sel(struct tegra_xudc *xudc,
				  struct usb_ctrlrequest *ctrl)
{
	if (ctrl->bRequestType != (USB_DIR_OUT | USB_RECIP_DEVICE |
				     USB_TYPE_STANDARD))
		return -EINVAL;

	if (xudc->device_state == USB_STATE_DEFAULT)
		return -EINVAL;

	if ((le16_to_cpu(ctrl->wIndex) != 0) ||
	    (le16_to_cpu(ctrl->wValue) != 0) ||
	    (le16_to_cpu(ctrl->wLength) != 6))
		return -EINVAL;

	return tegra_xudc_ep0_queue_data(xudc, &xudc->sel_timing,
					 sizeof(xudc->sel_timing),
					 set_sel_complete);
}

static void set_isoch_delay_complete(struct usb_ep *ep, struct usb_request *req)
{
	/* Nothing to do with isoch delay */
}

static int tegra_xudc_ep0_set_isoch_delay(struct tegra_xudc *xudc,
					  struct usb_ctrlrequest *ctrl)
{
	u32 delay = le16_to_cpu(ctrl->wValue);

	if (ctrl->bRequestType != (USB_DIR_OUT | USB_RECIP_DEVICE |
				   USB_TYPE_STANDARD))
		return -EINVAL;

	if ((delay > 65535) || (le16_to_cpu(ctrl->wIndex) != 0) ||
	    (le16_to_cpu(ctrl->wLength) != 0))
		return -EINVAL;

	xudc->isoch_delay = delay;

	return tegra_xudc_ep0_queue_status(xudc, set_isoch_delay_complete);
}

static void set_address_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct tegra_xudc *xudc = req->context;

	if ((xudc->device_state == USB_STATE_DEFAULT) &&
	    (xudc->dev_addr != 0)) {
		xudc->device_state = USB_STATE_ADDRESS;
		usb_gadget_set_state(&xudc->gadget, xudc->device_state);
	} else if ((xudc->device_state == USB_STATE_ADDRESS) &&
		   (xudc->dev_addr == 0)) {
		xudc->device_state = USB_STATE_DEFAULT;
		usb_gadget_set_state(&xudc->gadget, xudc->device_state);
	}
}

static int tegra_xudc_ep0_set_address(struct tegra_xudc *xudc,
				      struct usb_ctrlrequest *ctrl)
{
	struct tegra_xudc_ep *ep0 = &xudc->ep[0];
	u32 val, addr = le16_to_cpu(ctrl->wValue);

	if (ctrl->bRequestType != (USB_DIR_OUT | USB_RECIP_DEVICE |
				     USB_TYPE_STANDARD))
		return -EINVAL;

	if ((addr > 127) || (le16_to_cpu(ctrl->wIndex) != 0) ||
	    (le16_to_cpu(ctrl->wLength) != 0))
		return -EINVAL;

	if (xudc->device_state == USB_STATE_CONFIGURED)
		return -EINVAL;

	dev_dbg(xudc->dev, "set address: %u\n", addr);

	xudc->dev_addr = addr;
	val = xudc_readl(xudc, CTRL);
	val &= ~(CTRL_DEVADDR_MASK << CTRL_DEVADDR_SHIFT);
	val |= addr << CTRL_DEVADDR_SHIFT;
	xudc_writel(xudc, val, CTRL);

	ep_ctx_write_devaddr(ep0->context, addr);

	return tegra_xudc_ep0_queue_status(xudc, set_address_complete);
}

static int tegra_xudc_ep0_standard_req(struct tegra_xudc *xudc,
				      struct usb_ctrlrequest *ctrl)
{
	int ret;

	switch (ctrl->bRequest) {
	case USB_REQ_GET_STATUS:
		dev_dbg(xudc->dev, "USB_REQ_GET_STATUS\n");
		ret = tegra_xudc_ep0_get_status(xudc, ctrl);
		break;
	case USB_REQ_SET_ADDRESS:
		dev_dbg(xudc->dev, "USB_REQ_SET_ADDRESS\n");
		ret = tegra_xudc_ep0_set_address(xudc, ctrl);
		break;
	case USB_REQ_SET_SEL:
		dev_dbg(xudc->dev, "USB_REQ_SET_SEL\n");
		ret = tegra_xudc_ep0_set_sel(xudc, ctrl);
		break;
	case USB_REQ_SET_ISOCH_DELAY:
		dev_dbg(xudc->dev, "USB_REQ_SET_ISOCH_DELAY\n");
		ret = tegra_xudc_ep0_set_isoch_delay(xudc, ctrl);
		break;
	case USB_REQ_CLEAR_FEATURE:
	case USB_REQ_SET_FEATURE:
		dev_dbg(xudc->dev, "USB_REQ_CLEAR/SET_FEATURE\n");
		ret = tegra_xudc_ep0_set_feature(xudc, ctrl);
		break;
	case USB_REQ_SET_CONFIGURATION:
		dev_dbg(xudc->dev, "USB_REQ_SET_CONFIGURATION\n");
		/*
		 * In theory we need to clear RUN bit before status stage of
		 * deconfig request sent, but this seems to be causing problems.
		 * Clear RUN once all endpoints are disabled instead.
		 */
	default:
		ret = tegra_xudc_ep0_delegate_req(xudc, ctrl);
		break;
	}

	return ret;
}

static void tegra_xudc_handle_ep0_setup_packet(struct tegra_xudc *xudc,
					       struct usb_ctrlrequest *ctrl,
					       u16 seq_num)
{
	int ret;

	xudc->setup_seq_num = seq_num;

	/* Ensure EP0 is unhalted. */
	ep_unhalt(xudc, 0);

	/*
	 * On Tegra210, setup packets with sequence numbers 0xfffe or 0xffff
	 * are invalid.  Halt EP0 until we get a valid packet.
	 */
	if (xudc->soc->invalid_seq_num &&
	    (seq_num == 0xfffe || seq_num == 0xffff)) {
		dev_warn(xudc->dev, "invalid sequence number detected\n");
		ep_halt(xudc, 0);
		return;
	}

	if (ctrl->wLength)
		xudc->setup_state = (ctrl->bRequestType & USB_DIR_IN) ?
			DATA_STAGE_XFER :  DATA_STAGE_RECV;
	else
		xudc->setup_state = STATUS_STAGE_XFER;

	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD)
		ret = tegra_xudc_ep0_standard_req(xudc, ctrl);
	else
		ret = tegra_xudc_ep0_delegate_req(xudc, ctrl);

	if (ret < 0) {
		dev_warn(xudc->dev, "setup request failed: %d\n", ret);
		xudc->setup_state = WAIT_FOR_SETUP;
		ep_halt(xudc, 0);
	}
}

static void tegra_xudc_handle_ep0_event(struct tegra_xudc *xudc,
					struct tegra_xudc_trb *event)
{
	struct usb_ctrlrequest *ctrl = (struct usb_ctrlrequest *)event;
	u16 seq_num = trb_read_seq_num(event);

	if (xudc->ucd)
		cancel_delayed_work(&xudc->non_std_charger_work);
	if (xudc->setup_state != WAIT_FOR_SETUP) {
		/*
		 * The controller is in the process of handling another
		 * setup request.  Queue subsequent requests and handle
		 * the last one once the controller reports a sequence
		 * number error.
		 */
		memcpy(&xudc->setup_packet.ctrl_req, ctrl, sizeof(*ctrl));
		xudc->setup_packet.seq_num = seq_num;
		xudc->queued_setup_packet = true;
	} else {
		tegra_xudc_handle_ep0_setup_packet(xudc, ctrl, seq_num);
	}
}

static struct tegra_xudc_request *
trb_to_request(struct tegra_xudc_ep *ep, struct tegra_xudc_trb *trb)
{
	struct tegra_xudc_request *req;

	list_for_each_entry(req, &ep->queue, list) {
		if (!req->trbs_queued)
			break;

		if (trb_in_request(ep, req, trb))
			return req;
	}

	return NULL;
}

static void tegra_xudc_handle_transfer_completion(struct tegra_xudc *xudc,
						  struct tegra_xudc_ep *ep,
						  struct tegra_xudc_trb *event)
{
	struct tegra_xudc_request *req;
	struct tegra_xudc_trb *trb;
	bool short_packet;

	short_packet = (trb_read_cmpl_code(event) ==
			TRB_CMPL_CODE_SHORT_PACKET);

	trb = trb_phys_to_virt(ep, trb_read_data_ptr(event));
	req = trb_to_request(ep, trb);
	/*
	 * TDs are complete on short packet or when the completed TRB is the
	 * last TRB in the TD (the CHAIN bit is unset).
	 */
	if (req && (short_packet || (!trb_read_chain(trb) &&
		(req->trbs_needed == req->trbs_queued)))) {
		struct tegra_xudc_trb *last = req->last_trb;
		unsigned int residual;

		residual = trb_read_transfer_len(event);
		req->usb_req.actual = req->usb_req.length - residual;

		dev_dbg(xudc->dev, "bytes transferred %u / %u\n",
			req->usb_req.actual, req->usb_req.length);

		tegra_xudc_req_done(ep, req, 0);

		if (ep->desc && usb_endpoint_xfer_control(ep->desc))
			tegra_xudc_ep0_req_done(xudc);

		/*
		 * Advance the dequeue pointer past the end of the current TD
		 * on short packet completion.
		 */
		if (short_packet) {
			ep->deq_ptr = (last - ep->transfer_ring) + 1;
			if (ep->deq_ptr == XUDC_TRANSFER_RING_SIZE - 1)
				ep->deq_ptr = 0;
		}
	} else if (!req) {
		dev_warn(xudc->dev, "transfer event on dequeued request\n");
	}

	if (ep->desc)
		tegra_xudc_ep_kick_queue(ep);
}

static void tegra_xudc_handle_transfer_event(struct tegra_xudc *xudc,
					     struct tegra_xudc_trb *event)
{
	unsigned int ep_index = trb_read_endpoint_id(event);
	struct tegra_xudc_ep *ep = &xudc->ep[ep_index];
	struct tegra_xudc_trb *trb;
	u16 comp_code;

	if (ep_ctx_read_state(ep->context) == EP_STATE_DISABLED) {
		dev_warn(xudc->dev, "transfer event on disabled ep %u\n",
			 ep_index);
		return;
	}

	/* Update transfer ring dequeue pointer. */
	trb = trb_phys_to_virt(ep, trb_read_data_ptr(event));
	ep->deq_ptr = (trb - ep->transfer_ring) + 1;
	if (ep->deq_ptr == XUDC_TRANSFER_RING_SIZE - 1)
		ep->deq_ptr = 0;
	ep->ring_full = false;

	comp_code = trb_read_cmpl_code(event);
	switch (comp_code) {
	case TRB_CMPL_CODE_SUCCESS:
	case TRB_CMPL_CODE_SHORT_PACKET:
		tegra_xudc_handle_transfer_completion(xudc, ep, event);
		break;
	case TRB_CMPL_CODE_HOST_REJECTED:
		dev_info(xudc->dev, "stream rejected on ep %u\n", ep_index);

		ep->stream_rejected = true;
		break;
	case TRB_CMPL_CODE_PRIME_PIPE_RECEIVED:
		dev_info(xudc->dev, "prime pipe received on ep %u\n", ep_index);

		if (ep->stream_rejected) {
			ep->stream_rejected = false;
			/*
			 * An EP is stopped when a stream is rejected.  Wait
			 * for the EP to report that it is stopped and then
			 * un-stop it.
			 */
			ep_wait_for_stopped(xudc, ep_index);
		}
		tegra_xudc_ep_ring_doorbell(ep);
		break;
	case TRB_CMPL_CODE_BABBLE_DETECTED_ERR:
		/*
		 * Wait for the EP to be stopped so the controller stops
		 * processing doorbells.
		 */
		ep_wait_for_stopped(xudc, ep_index);
	case TRB_CMPL_CODE_STREAM_NUMP_ERROR:
	case TRB_CMPL_CODE_CTRL_DIR_ERR:
	case TRB_CMPL_CODE_INVALID_STREAM_TYPE_ERR:
	case TRB_CMPL_CODE_RING_UNDERRUN:
	case TRB_CMPL_CODE_RING_OVERRUN:
	case TRB_CMPL_CODE_ISOCH_BUFFER_OVERRUN:
	case TRB_CMPL_CODE_USB_TRANS_ERR:
	case TRB_CMPL_CODE_TRB_ERR:
		dev_err(xudc->dev, "completion error %#x on ep %u\n",
			comp_code, ep_index);

		ep_halt(xudc, ep_index);
		break;
	case TRB_CMPL_CODE_CTRL_SEQNUM_ERR:
		dev_info(xudc->dev, "sequence number error\n");

		/*
		 * Kill any queued control request and skip to the last
		 * setup packet we received.
		 */
		tegra_xudc_ep_nuke(ep, -EINVAL);
		xudc->setup_state = WAIT_FOR_SETUP;
		if (!xudc->queued_setup_packet)
			break;

		tegra_xudc_handle_ep0_setup_packet(xudc,
						   &xudc->setup_packet.ctrl_req,
						   xudc->setup_packet.seq_num);
		xudc->queued_setup_packet = false;
		break;
	case TRB_CMPL_CODE_STOPPED:
		dev_dbg(xudc->dev, "stop completion code on ep %u\n",
			ep_index);

		/* Disconnected. */
		tegra_xudc_ep_nuke(ep, -ECONNREFUSED);
		break;
	default:
		dev_dbg(xudc->dev, "completion event %#x on ep %u\n",
			comp_code, ep_index);
		break;
	}
}

static void tegra_xudc_reset(struct tegra_xudc *xudc)
{
	struct tegra_xudc_ep *ep0 = &xudc->ep[0];
	dma_addr_t deq_ptr;
	unsigned int i;

	xudc->setup_state = WAIT_FOR_SETUP;
	xudc->device_state = USB_STATE_DEFAULT;
	usb_gadget_set_state(&xudc->gadget, xudc->device_state);

	ep_unpause_all(xudc);

	for (i = 0; i < ARRAY_SIZE(xudc->ep); i++)
		tegra_xudc_ep_nuke(&xudc->ep[i], -ESHUTDOWN);

	/*
	 * Reset sequence number and dequeue pointer to flush the transfer
	 * ring.
	 */
	ep0->deq_ptr = ep0->enq_ptr;
	ep0->ring_full = false;

	xudc->setup_seq_num = 0;
	xudc->queued_setup_packet = false;

	ep_ctx_write_rsvd(ep0->context, 0);
	ep_ctx_write_partial_td(ep0->context, 0);
	ep_ctx_write_splitxstate(ep0->context, 0);
	ep_ctx_write_seq_num(ep0->context, 0);

	deq_ptr = trb_virt_to_phys(ep0, &ep0->transfer_ring[ep0->deq_ptr]);
	ep_ctx_write_deq_ptr(ep0->context, deq_ptr);
	ep_ctx_write_dcs(ep0->context, ep0->pcs);

	ep_unhalt_all(xudc);
	ep_reload(xudc, 0);
	ep_unpause(xudc, 0);
}

static void tegra_xudc_port_connect(struct tegra_xudc *xudc)
{
	struct tegra_xudc_ep *ep0 = &xudc->ep[0];
	u16 maxpacket;
	u32 val;

	val = (xudc_readl(xudc, PORTSC) >> PORTSC_PS_SHIFT) & PORTSC_PS_MASK;
	switch (val) {
	case PORTSC_PS_LS:
		xudc->gadget.speed = USB_SPEED_LOW;
		break;
	case PORTSC_PS_FS:
		xudc->gadget.speed = USB_SPEED_FULL;
		break;
	case PORTSC_PS_HS:
		xudc->gadget.speed = USB_SPEED_HIGH;
		break;
	case PORTSC_PS_SS:
		xudc->gadget.speed = USB_SPEED_SUPER;
		break;
	default:
		xudc->gadget.speed = USB_SPEED_UNKNOWN;
		break;
	}

	xudc->device_state = USB_STATE_DEFAULT;
	usb_gadget_set_state(&xudc->gadget, xudc->device_state);

	xudc->setup_state = WAIT_FOR_SETUP;

	if (xudc->gadget.speed == USB_SPEED_SUPER)
		maxpacket = 512;
	else
		maxpacket = 64;
	ep_ctx_write_max_packet_size(ep0->context, maxpacket);
	tegra_xudc_ep0_desc.wMaxPacketSize = cpu_to_le16(maxpacket);
	usb_ep_set_maxpacket_limit(&ep0->usb_ep, maxpacket);

	if (!u1_enable) {
		val = xudc_readl(xudc, PORTPM);
		val &= ~(PORTPM_U1TIMEOUT_MASK << PORTPM_U1TIMEOUT_SHIFT);
		xudc_writel(xudc, val, PORTPM);
	}
	if (!u2_enable) {
		val = xudc_readl(xudc, PORTPM);
		val &= ~(PORTPM_U2TIMEOUT_MASK << PORTPM_U2TIMEOUT_SHIFT);
		xudc_writel(xudc, val, PORTPM);
	}
	if (xudc->gadget.speed <= USB_SPEED_HIGH) {
		val = xudc_readl(xudc, PORTPM);
		val &= ~(PORTPM_L1S_MASK << PORTPM_L1S_SHIFT);
		if (lpm_enable)
			val |= PORTPM_L1S_ACCEPT << PORTPM_L1S_SHIFT;
		else
			val |= PORTPM_L1S_NYET << PORTPM_L1S_SHIFT;
		xudc_writel(xudc, val, PORTPM);
	}

	val = xudc_readl(xudc, ST);
	if (val & ST_RC)
		xudc_writel(xudc, ST_RC, ST);
}

static void tegra_xudc_port_disconnect(struct tegra_xudc *xudc)
{
	tegra_xudc_reset(xudc);
	if (xudc->driver && xudc->driver->disconnect) {
		spin_unlock(&xudc->lock);
		xudc->driver->disconnect(&xudc->gadget);
		spin_lock(&xudc->lock);
	}

	xudc->device_state = USB_STATE_NOTATTACHED;
	usb_gadget_set_state(&xudc->gadget, xudc->device_state);

	complete(&xudc->disconnect_complete);
}

static void tegra_xudc_port_reset(struct tegra_xudc *xudc)
{
	tegra_xudc_reset(xudc);
	if (xudc->driver) {
		spin_unlock(&xudc->lock);
		usb_gadget_udc_reset(&xudc->gadget, xudc->driver);
		spin_lock(&xudc->lock);
	}
	tegra_xudc_port_connect(xudc);
}

static void tegra_xudc_port_suspend(struct tegra_xudc *xudc)
{
	dev_dbg(xudc->dev, "port suspend\n");
	xudc->resume_state = xudc->device_state;
	xudc->device_state = USB_STATE_SUSPENDED;
	usb_gadget_set_state(&xudc->gadget, xudc->device_state);
	if (xudc->driver->suspend) {
		spin_unlock(&xudc->lock);
		xudc->driver->suspend(&xudc->gadget);
		spin_lock(&xudc->lock);
	}
}

static void tegra_xudc_port_resume(struct tegra_xudc *xudc)
{
	dev_dbg(xudc->dev, "port resume\n");
	tegra_xudc_resume_device_state(xudc);
	if (xudc->driver->resume) {
		spin_unlock(&xudc->lock);
		xudc->driver->resume(&xudc->gadget);
		spin_lock(&xudc->lock);
	}
}

static inline void clear_port_change(struct tegra_xudc *xudc, u32 flag)
{
	u32 val;

	val = xudc_readl(xudc, PORTSC);
	val &= ~PORTSC_CHANGE_MASK;
	val |= flag;
	xudc_writel(xudc, val, PORTSC);
}

static void __tegra_xudc_handle_port_status(struct tegra_xudc *xudc)
{
	u32 portsc, porthalt;

	porthalt = xudc_readl(xudc, PORTHALT);
	if ((porthalt & PORTHALT_STCHG_REQ) &&
	    (porthalt & PORTHALT_HALT_LTSSM)) {
		dev_dbg(xudc->dev, "STCHG_REQ, PORTHALT = %#x\n", porthalt);
		porthalt &= ~PORTHALT_HALT_LTSSM;
		xudc_writel(xudc, porthalt, PORTHALT);
	}

	portsc = xudc_readl(xudc, PORTSC);
	if ((portsc & PORTSC_PRC) && (portsc & PORTSC_PR)) {
		dev_dbg(xudc->dev, "PRC, PR, PORTSC = %#x\n", portsc);
		clear_port_change(xudc, PORTSC_PRC | PORTSC_PED);
#define TOGGLE_VBUS_WAIT_MS 100
		if (xudc->soc->port_reset_quirk) {
			schedule_delayed_work(&xudc->port_reset_war_work,
				msecs_to_jiffies(TOGGLE_VBUS_WAIT_MS));
			xudc->wait_for_sec_prc = 1;
		}
	}

	if ((portsc & PORTSC_PRC) && !(portsc & PORTSC_PR)) {
		dev_dbg(xudc->dev, "PRC, Not PR, PORTSC = %#x\n", portsc);
		clear_port_change(xudc, PORTSC_PRC | PORTSC_PED);
		tegra_xudc_port_reset(xudc);
		cancel_delayed_work(&xudc->port_reset_war_work);
		xudc->wait_for_sec_prc = 0;
	}

	portsc = xudc_readl(xudc, PORTSC);
	if (portsc & PORTSC_WRC) {
		dev_dbg(xudc->dev, "WRC, PORTSC = %#x\n", portsc);
		clear_port_change(xudc, PORTSC_WRC | PORTSC_PED);
		if (!(xudc_readl(xudc, PORTSC) & PORTSC_WPR))
			tegra_xudc_port_reset(xudc);
	}

	portsc = xudc_readl(xudc, PORTSC);
	if (portsc & PORTSC_CSC) {
		dev_dbg(xudc->dev, "CSC, PORTSC = %#x\n", portsc);
		clear_port_change(xudc, PORTSC_CSC);
		if (portsc & PORTSC_CCS)
			tegra_xudc_port_connect(xudc);
		else
			tegra_xudc_port_disconnect(xudc);
		if (xudc->wait_csc) {
			cancel_delayed_work(&xudc->plc_reset_work);
			xudc->wait_csc = false;
		}
	}

	portsc = xudc_readl(xudc, PORTSC);
	if (portsc & PORTSC_PLC) {
		u32 pls = (portsc >> PORTSC_PLS_SHIFT) & PORTSC_PLS_MASK;

		dev_dbg(xudc->dev, "PLC, PORTSC = %#x\n", portsc);
		clear_port_change(xudc, PORTSC_PLC);
		switch (pls) {
		case PORTSC_PLS_U3:
			tegra_xudc_port_suspend(xudc);
			break;
		case PORTSC_PLS_U0:
			if (xudc->gadget.speed < USB_SPEED_SUPER)
				tegra_xudc_port_resume(xudc);
			break;
		case PORTSC_PLS_RESUME:
			if (xudc->gadget.speed == USB_SPEED_SUPER)
				tegra_xudc_port_resume(xudc);
			break;
		case PORTSC_PLS_INACTIVE:
			schedule_delayed_work(&xudc->plc_reset_work,
					msecs_to_jiffies(TOGGLE_VBUS_WAIT_MS));
			xudc->wait_csc = true;
			break;
		default:
			break;
		}
	}

	if (portsc & PORTSC_CEC) {
		dev_warn(xudc->dev, "CEC, PORTSC = %#x\n", portsc);
		clear_port_change(xudc, PORTSC_CEC);
	}

	dev_dbg(xudc->dev, "PORTSC = %#x\n", xudc_readl(xudc, PORTSC));
}

static void tegra_xudc_handle_port_status(struct tegra_xudc *xudc)
{
	while ((xudc_readl(xudc, PORTSC) & PORTSC_CHANGE_MASK) ||
	       (xudc_readl(xudc, PORTHALT) & PORTHALT_STCHG_REQ))
		__tegra_xudc_handle_port_status(xudc);
}

static void tegra_xudc_handle_event(struct tegra_xudc *xudc,
				    struct tegra_xudc_trb *event)
{
	u32 type = trb_read_type(event);

	dump_trb(xudc, "EVENT", event);

	switch (type) {
	case TRB_TYPE_PORT_STATUS_CHANGE_EVENT:
		tegra_xudc_handle_port_status(xudc);
		break;
	case TRB_TYPE_TRANSFER_EVENT:
		tegra_xudc_handle_transfer_event(xudc, event);
		break;
	case TRB_TYPE_SETUP_PACKET_EVENT:
		tegra_xudc_handle_ep0_event(xudc, event);
		break;
	default:
		dev_info(xudc->dev, "Unrecognized TRB type = %#x\n", type);
		break;
	}
}

static void tegra_xudc_process_event_ring(struct tegra_xudc *xudc)
{
	struct tegra_xudc_trb *event;
	dma_addr_t erdp;

	while (true) {
		event = xudc->event_ring[xudc->event_ring_index] +
			xudc->event_ring_deq_ptr;

		if (trb_read_cycle(event) != xudc->ccs)
			break;

		tegra_xudc_handle_event(xudc, event);

		xudc->event_ring_deq_ptr++;
		if (xudc->event_ring_deq_ptr == XUDC_EVENT_RING_SIZE) {
			xudc->event_ring_deq_ptr = 0;
			xudc->event_ring_index++;
		}
		if (xudc->event_ring_index == XUDC_NR_EVENT_RINGS) {
			xudc->event_ring_index = 0;
			xudc->ccs = !xudc->ccs;
		}
	}

	erdp = xudc->event_ring_phys[xudc->event_ring_index] +
		xudc->event_ring_deq_ptr * sizeof(*event);
	xudc_writel(xudc, upper_32_bits(erdp), ERDPHI);
	xudc_writel(xudc, lower_32_bits(erdp) | ERDPLO_EHB, ERDPLO);
}

static irqreturn_t tegra_xudc_irq(int irq, void *data)
{
	struct tegra_xudc *xudc = data;
	unsigned long flags;
	u32 val;

	val = xudc_readl(xudc, ST);
	if (!(val & ST_IP))
		return IRQ_NONE;
	xudc_writel(xudc, ST_IP, ST);

	spin_lock_irqsave(&xudc->lock, flags);
	tegra_xudc_process_event_ring(xudc);
	spin_unlock_irqrestore(&xudc->lock, flags);

	return IRQ_HANDLED;
}

static int tegra_xudc_alloc_ep(struct tegra_xudc *xudc, unsigned int index)
{
	struct tegra_xudc_ep *ep = &xudc->ep[index];

	ep->xudc = xudc;
	ep->index = index;
	ep->context = &xudc->ep_context[index];
	INIT_LIST_HEAD(&ep->queue);

	/*
	 * EP1 would be the input endpoint corresponding to EP0, but since
	 * EP0 is bi-directional, EP1 is unused.
	 */
	if (index == 1)
		return 0;

	ep->transfer_ring = dma_pool_alloc(xudc->transfer_ring_pool,
					   GFP_KERNEL,
					   &ep->transfer_ring_phys);
	if (!ep->transfer_ring)
		return -ENOMEM;

	if (index) {
		snprintf(ep->name, sizeof(ep->name), "ep%u%s", index / 2,
			 (index % 2 == 0) ? "out" : "in");
		ep->usb_ep.name = ep->name;
		usb_ep_set_maxpacket_limit(&ep->usb_ep, 1024);
		ep->usb_ep.max_streams = 16;
		ep->usb_ep.ops = &tegra_xudc_ep_ops;
		ep->usb_ep.caps.type_bulk = true;
		ep->usb_ep.caps.type_int = true;
		if (index & 1)
			ep->usb_ep.caps.dir_in = true;
		else
			ep->usb_ep.caps.dir_out = true;
		list_add_tail(&ep->usb_ep.ep_list, &xudc->gadget.ep_list);
	} else {
		strcpy(ep->name, "ep0");
		ep->usb_ep.name = ep->name;
		usb_ep_set_maxpacket_limit(&ep->usb_ep, 64);
		ep->usb_ep.ops = &tegra_xudc_ep0_ops;
		ep->usb_ep.caps.type_control = true;
		ep->usb_ep.caps.dir_in = true;
		ep->usb_ep.caps.dir_out = true;
	}

	return 0;
}

static void tegra_xudc_free_ep(struct tegra_xudc *xudc, unsigned int index)
{
	struct tegra_xudc_ep *ep = &xudc->ep[index];

	/*
	 * EP1 would be the input endpoint corresponding to EP0, but since
	 * EP0 is bi-directional, EP1 is unused.
	 */
	if (index == 1)
		return;

	dma_pool_free(xudc->transfer_ring_pool, ep->transfer_ring,
		      ep->transfer_ring_phys);
}

static int tegra_xudc_alloc_eps(struct tegra_xudc *xudc)
{
	struct usb_request *req;
	unsigned int i;
	int err;

	xudc->ep_context =
		dma_zalloc_coherent(xudc->dev, XUDC_NR_EPS *
				    sizeof(*xudc->ep_context),
				    &xudc->ep_context_phys, GFP_KERNEL);
	if (!xudc->ep_context)
		return -ENOMEM;

	xudc->transfer_ring_pool =
		dmam_pool_create(dev_name(xudc->dev), xudc->dev,
				 XUDC_TRANSFER_RING_SIZE *
				 sizeof(struct tegra_xudc_trb),
				 sizeof(struct tegra_xudc_trb), 0);
	if (!xudc->transfer_ring_pool) {
		err = -ENOMEM;
		goto free_ep_context;
	}

	INIT_LIST_HEAD(&xudc->gadget.ep_list);
	for (i = 0; i < ARRAY_SIZE(xudc->ep); i++) {
		err = tegra_xudc_alloc_ep(xudc, i);
		if (err < 0)
			goto free_eps;
	}

	req = tegra_xudc_ep_alloc_request(&xudc->ep[0].usb_ep, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto free_eps;
	}
	xudc->ep0_req = to_xudc_req(req);

	return 0;

free_eps:
	for (; i > 0; i--)
		tegra_xudc_free_ep(xudc, i - 1);
free_ep_context:
	dma_free_coherent(xudc->dev, XUDC_NR_EPS * sizeof(*xudc->ep_context),
			  xudc->ep_context, xudc->ep_context_phys);
	return err;
}

static void tegra_xudc_init_eps(struct tegra_xudc *xudc)
{
	xudc_writel(xudc, lower_32_bits(xudc->ep_context_phys), ECPLO);
	xudc_writel(xudc, upper_32_bits(xudc->ep_context_phys), ECPHI);
}

static void tegra_xudc_free_eps(struct tegra_xudc *xudc)
{
	unsigned int i;

	tegra_xudc_ep_free_request(&xudc->ep[0].usb_ep,
				   &xudc->ep0_req->usb_req);

	for (i = 0; i < ARRAY_SIZE(xudc->ep); i++)
		tegra_xudc_free_ep(xudc, i);

	dma_free_coherent(xudc->dev, XUDC_NR_EPS * sizeof(*xudc->ep_context),
			  xudc->ep_context, xudc->ep_context_phys);
}

static int tegra_xudc_alloc_event_ring(struct tegra_xudc *xudc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(xudc->event_ring); i++) {
		xudc->event_ring[i] =
			dma_alloc_coherent(xudc->dev, XUDC_EVENT_RING_SIZE *
					   sizeof(*xudc->event_ring[i]),
					   &xudc->event_ring_phys[i],
					   GFP_KERNEL);
		if (!xudc->event_ring[i])
			goto free_dma;
	}

	return 0;

free_dma:
	for (; i > 0; i--) {
		dma_free_coherent(xudc->dev, XUDC_EVENT_RING_SIZE *
				  sizeof(*xudc->event_ring[i - 1]),
				  xudc->event_ring[i - 1],
				  xudc->event_ring_phys[i - 1]);
	}
	return -ENOMEM;
}

static void tegra_xudc_init_event_ring(struct tegra_xudc *xudc)
{
	unsigned int i;
	u32 val;

	for (i = 0; i < ARRAY_SIZE(xudc->event_ring); i++) {
		memset(xudc->event_ring[i], 0, XUDC_EVENT_RING_SIZE *
		       sizeof(*xudc->event_ring[i]));

		val = xudc_readl(xudc, ERSTSZ);
		val &= ~(ERSTSZ_ERSTXSZ_MASK << ERSTSZ_ERSTXSZ_SHIFT(i));
		val |= XUDC_EVENT_RING_SIZE << ERSTSZ_ERSTXSZ_SHIFT(i);
		xudc_writel(xudc, val, ERSTSZ);

		xudc_writel(xudc, lower_32_bits(xudc->event_ring_phys[i]),
			    ERSTXBALO(i));
		xudc_writel(xudc, upper_32_bits(xudc->event_ring_phys[i]),
			    ERSTXBAHI(i));
	}

	val = lower_32_bits(xudc->event_ring_phys[0]);
	xudc_writel(xudc, val, ERDPLO);
	val |= EREPLO_ECS;
	xudc_writel(xudc, val, EREPLO);

	val = upper_32_bits(xudc->event_ring_phys[0]);
	xudc_writel(xudc, val, ERDPHI);
	xudc_writel(xudc, val, EREPHI);

	xudc->ccs = true;
	xudc->event_ring_index = 0;
	xudc->event_ring_deq_ptr = 0;
}

static void tegra_xudc_free_event_ring(struct tegra_xudc *xudc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(xudc->event_ring); i++) {
		dma_free_coherent(xudc->dev, XUDC_EVENT_RING_SIZE *
				  sizeof(*xudc->event_ring[i]),
				  xudc->event_ring[i],
				  xudc->event_ring_phys[i]);
	}
}

static void tegra_xudc_fpci_ipfs_init(struct tegra_xudc *xudc)
{
	u32 val;

	if (XUDC_IS_T210(xudc)) {
		val = ipfs_readl(xudc, IPFS_XUSB_DEV_CONFIGURATION);
		val |= IPFS_XUSB_DEV_CONFIGURATION_EN_FPCI;
		ipfs_writel(xudc, val, IPFS_XUSB_DEV_CONFIGURATION);
		udelay(10);
	}

	/* Enable bus master */
	val = XUSB_DEV_CFG_1_IO_SPACE_EN | XUSB_DEV_CFG_1_MEMORY_SPACE_EN |
		XUSB_DEV_CFG_1_BUS_MASTER_EN;
	fpci_writel(xudc, val, XUSB_DEV_CFG_1);

	/* Program BAR0 space */
	val = fpci_readl(xudc, XUSB_DEV_CFG_4);
	val &= ~(XUSB_DEV_CFG_4_BASE_ADDR_MASK <<
		 XUSB_DEV_CFG_4_BASE_ADDR_SHIFT);
	val |= xudc->phys_base & (XUSB_DEV_CFG_4_BASE_ADDR_MASK <<
				  XUSB_DEV_CFG_4_BASE_ADDR_SHIFT);
	fpci_writel(xudc, val, XUSB_DEV_CFG_4);
	fpci_writel(xudc, upper_32_bits(xudc->phys_base), XUSB_DEV_CFG_5);
	usleep_range(100, 200);

	if (XUDC_IS_T210(xudc)) {
		/* Enable interrupt assertion */
		val = ipfs_readl(xudc, IPFS_XUSB_DEV_INTR_MASK);
		val |= IPFS_XUSB_DEV_INTR_MASK_IP_INT_MASK;
		ipfs_writel(xudc, val, IPFS_XUSB_DEV_INTR_MASK);
	}
}

static void tegra_xudc_device_params_init(struct tegra_xudc *xudc)
{
	u32 val, imod;

	if (XUDC_IS_T210(xudc)) {
		val = xudc_readl(xudc, BLCG);
		val |= BLCG_ALL;
		val &= ~(BLCG_DFPCI | BLCG_UFPCI | BLCG_FE |
				BLCG_COREPLL_PWRDN);
		val |= BLCG_IOPLL_0_PWRDN;
		val |= BLCG_IOPLL_1_PWRDN;
		val |= BLCG_IOPLL_2_PWRDN;
		xudc_writel(xudc, val, BLCG);
	} else if (!XUDC_IS_T210(xudc)) {
		/* T186 WAR: Disable BLCG COREPLL_PWRDN */
		val = xudc_readl(xudc, BLCG);
		val &= ~BLCG_COREPLL_PWRDN;
		xudc_writel(xudc, val, BLCG);
	}

	if (xudc->soc->port_speed_quirk)
		tegra_xudc_limit_port_speed(xudc);

	/* Set a reasonable U3 exit timer value. */
	val = xudc_readl(xudc, SSPX_CORE_PADCTL4);
	val &= ~(SSPX_CORE_PADCTL4_RXDAT_VLD_TIMEOUT_U3_MASK <<
		 SSPX_CORE_PADCTL4_RXDAT_VLD_TIMEOUT_U3_SHIFT);
	val |= 0x5dc0 << SSPX_CORE_PADCTL4_RXDAT_VLD_TIMEOUT_U3_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_PADCTL4);

	/* Default ping LFPS tBurst is too large. */
	val = xudc_readl(xudc, SSPX_CORE_CNT0);
	val &= ~(SSPX_CORE_CNT0_PING_TBURST_MASK <<
		 SSPX_CORE_CNT0_PING_TBURST_SHIFT);
	val |= 0xa << SSPX_CORE_CNT0_PING_TBURST_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT0);

	/* Default tPortConfiguration timeout is too small. */
	val = xudc_readl(xudc, SSPX_CORE_CNT30);
	val &= ~(SSPX_CORE_CNT30_LMPITP_TIMER_MASK <<
		 SSPX_CORE_CNT30_LMPITP_TIMER_SHIFT);
	val |= 0x978 << SSPX_CORE_CNT30_LMPITP_TIMER_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT30);

	if (lpm_enable) {
		/* Set L1 resume duration to 95 us. */
		val = xudc_readl(xudc, HSFSPI_COUNT13);
		val &= ~(HSFSPI_COUNT13_U2_RESUME_K_DURATION_MASK <<
				HSFSPI_COUNT13_U2_RESUME_K_DURATION_SHIFT);
		val |= 0x2c88 << HSFSPI_COUNT13_U2_RESUME_K_DURATION_SHIFT;
		xudc_writel(xudc, val, HSFSPI_COUNT13);
	}

	/*
	 * Compliacne suite appears to be violating polling LFPS tBurst max
	 * of 1.4us.  Send 1.45us instead.
	 */
	val = xudc_readl(xudc, SSPX_CORE_CNT32);
	val &= ~(SSPX_CORE_CNT32_POLL_TBURST_MAX_MASK <<
		 SSPX_CORE_CNT32_POLL_TBURST_MAX_SHIFT);
	val |= 0xb0 << SSPX_CORE_CNT32_POLL_TBURST_MAX_SHIFT;
	xudc_writel(xudc, val, SSPX_CORE_CNT32);

	if (XUDC_IS_T186(xudc)) {
		/* Increase HS link stability */
		xudc_writel(xudc, 0x927c0, HSFSPI_COUNT16);

		/* Change INIT value of "NV_PROJ__XUSB_DEV_XHCI_HSFSPI_COUNT0"
		 * register from 0x12c to 0x3E8. This counter is used by xUSB
		 * device to respond to HS detection handshake after the
		 * detection of SE0 from host. */
		xudc_writel(xudc, 0x3e8, HSFSPI_COUNT0);
	}

	/* Direct HS/FS port instance to RxDetect. */
	val = xudc_readl(xudc, CFG_DEV_FE);
	val &= ~(CFG_DEV_FE_PORTREGSEL_MASK << CFG_DEV_FE_PORTREGSEL_SHIFT);
	val |= CFG_DEV_FE_PORTREGSEL_HSFS_PI << CFG_DEV_FE_PORTREGSEL_SHIFT;
	xudc_writel(xudc, val, CFG_DEV_FE);

	val = xudc_readl(xudc, PORTSC);
	val &= ~(PORTSC_CHANGE_MASK | (PORTSC_PLS_MASK << PORTSC_PLS_SHIFT));
	val |= PORTSC_LWS | (PORTSC_PLS_RXDETECT << PORTSC_PLS_SHIFT);
	xudc_writel(xudc, val, PORTSC);

	/* Direct SS port instance to RxDetect. */
	val = xudc_readl(xudc, CFG_DEV_FE);
	val &= ~(CFG_DEV_FE_PORTREGSEL_MASK << CFG_DEV_FE_PORTREGSEL_SHIFT);
	val |= CFG_DEV_FE_PORTREGSEL_SS_PI << CFG_DEV_FE_PORTREGSEL_SHIFT;
	xudc_writel(xudc, val, CFG_DEV_FE);

	val = xudc_readl(xudc, PORTSC);
	val &= ~(PORTSC_CHANGE_MASK | (PORTSC_PLS_MASK << PORTSC_PLS_SHIFT));
	val |= PORTSC_LWS | (PORTSC_PLS_RXDETECT << PORTSC_PLS_SHIFT);
	xudc_writel(xudc, val, PORTSC);

	/* Restore port instance. */
	val = xudc_readl(xudc, CFG_DEV_FE);
	val &= ~(CFG_DEV_FE_PORTREGSEL_MASK << CFG_DEV_FE_PORTREGSEL_SHIFT);
	xudc_writel(xudc, val, CFG_DEV_FE);

	/*
	 * Enable INFINITE_SS_RETRY to prevent device from entering
	 * Disabled.Error when attached to buggy SuperSpeed hubs.
	 */
	val = xudc_readl(xudc, CFG_DEV_FE);
	val |= CFG_DEV_FE_INFINITE_SS_RETRY;
	xudc_writel(xudc, val, CFG_DEV_FE);

	/* Set interrupt moderation. */
	imod = XUDC_INTERRUPT_MODERATION_US * 4;
	val = xudc_readl(xudc, RT_IMOD);
	val &= ~((RT_IMOD_IMODI_MASK << RT_IMOD_IMODI_SHIFT) |
		 (RT_IMOD_IMODC_MASK << RT_IMOD_IMODC_SHIFT));
	val |= (imod << RT_IMOD_IMODI_SHIFT) | (imod << RT_IMOD_IMODC_SHIFT);
	xudc_writel(xudc, val, RT_IMOD);

	/* increase SSPI transaction timeout from 32us to 512us */
	val = xudc_readl(xudc, CFG_DEV_SSPI_XFER);
	val &= ~(CFG_DEV_SSPI_XFER_ACKTIMEOUT_MASK <<
		CFG_DEV_SSPI_XFER_ACKTIMEOUT_SHIFT);
	val |= (0xf000 & CFG_DEV_SSPI_XFER_ACKTIMEOUT_MASK) <<
		CFG_DEV_SSPI_XFER_ACKTIMEOUT_SHIFT;
	xudc_writel(xudc, val, CFG_DEV_SSPI_XFER);
}

static int tegra_xudc_phy_init(struct tegra_xudc *xudc)
{
	int err, i;

	for (i = 0; i < xudc->dev_mode_num; i++) {
		err = phy_init(xudc->utmi_phy[i]);
		if (err < 0)
			return err;
		err = phy_init(xudc->usb3_phy[i]);
		if (err < 0)
			goto exit_utmi_phy;
	}

	return 0;

exit_utmi_phy:
	for (i = 0; i < xudc->dev_mode_num; i++)
		phy_exit(xudc->utmi_phy[i]);

	return err;
}

static void tegra_xudc_phy_exit(struct tegra_xudc *xudc)
{
	int i;

	for (i = 0; i < xudc->dev_mode_num; i++) {
		phy_exit(xudc->usb3_phy[i]);
		phy_exit(xudc->utmi_phy[i]);
	}
}

static int tegra_xudc_clk_init(struct tegra_xudc *xudc)
{
	struct device *dev = xudc->dev;
	int ret = 0;
	unsigned int i;

	xudc->num_clks = of_count_phandle_with_args(dev->of_node, "clocks",
						    "#clock-cells");
	if (xudc->num_clks <= 0)
		return -EINVAL;

	xudc->clks = devm_kcalloc(dev, xudc->num_clks, sizeof(*xudc->clks),
				  GFP_KERNEL);
	if (!xudc->clks)
		return -ENOMEM;

	for (i = 0; i < xudc->num_clks; i++) {
		xudc->clks[i] = of_clk_get(dev->of_node, i);
		if (IS_ERR(xudc->clks[i])) {
			ret = PTR_ERR(xudc->clks[i]);
			goto error;
		}
	}

	return 0;

error:
	while (i--)
		clk_put(xudc->clks[i]);
	xudc->num_clks = 0;

	return ret;
}

static void tegra_xudc_clk_deinit(struct tegra_xudc *xudc)
{
	unsigned int i;

	for (i = 0; i < xudc->num_clks; i++) {
		clk_put(xudc->clks[i]);
	}
}

static int tegra_xudc_clk_enable(struct tegra_xudc *xudc)
{
	unsigned int i;
	int ret = 0;

	if (xudc->clk_enabled)
		return 0;

	for (i = 0; i < xudc->num_clks; i++) {
		ret = clk_prepare_enable(xudc->clks[i]);
		if (ret)
			goto error;
	}

	xudc->clk_enabled = true;

	return 0;

error:
	while (i--)
		clk_disable_unprepare(xudc->clks[i]);

	return ret;
}

static void tegra_xudc_clk_disable(struct tegra_xudc *xudc)
{
	unsigned int i;

	if (!xudc->clk_enabled)
		return;

	for (i = 0; i < xudc->num_clks; i++)
		clk_disable_unprepare(xudc->clks[i]);

	xudc->clk_enabled = false;
}

static void tegra_xudc_non_std_charger_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct tegra_xudc *xudc = container_of(dwork, struct tegra_xudc,
					       non_std_charger_work);
	unsigned long flags;

	if (xudc->ucd) {
		spin_lock_irqsave(&xudc->lock, flags);
		xudc->connect_type = EXTCON_CHG_USB_SLOW;
		spin_unlock_irqrestore(&xudc->lock, flags);
		tegra_ucd_set_charger_type(xudc->ucd,
					   EXTCON_CHG_USB_SLOW);
		tegra_xudc_update_wakelock(xudc);
	}
}

static const char * const tegra210_xudc_supply_names[] = {
	"hvdd_usb",
	"avddio_usb",
	"avdd_pll_utmip",
};

static const char * const tegra186_xudc_supply_names[] = {
	/* for USB2 pads */
	"avdd-usb",
};

static const char * const tegra194_xudc_supply_names[] = {
};

static struct tegra_xudc_soc_data tegra210_xudc_soc_data = {
	.device_id = XUDC_DEVICE_ID_T210,
	.supply_names = tegra210_xudc_supply_names,
	.num_supplies = ARRAY_SIZE(tegra210_xudc_supply_names),
	.u1_enable = false,
	.u2_enable = true,
	.lpm_enable = false,
	.invalid_seq_num = true,
	.pls_quirk = true,
	.port_reset_quirk = true,
	.port_speed_quirk = false,
};

static struct tegra_xudc_soc_data tegra210b01_xudc_soc_data = {
	.device_id = XUDC_DEVICE_ID_T210,
	.supply_names = tegra210_xudc_supply_names,
	.num_supplies = ARRAY_SIZE(tegra210_xudc_supply_names),
	.u1_enable = false,
	.u2_enable = true,
	.lpm_enable = false,
	.invalid_seq_num = false,
	.pls_quirk = false,
	.port_reset_quirk = true,
	.port_speed_quirk = false,
};

static struct tegra_xudc_soc_data tegra186_xudc_soc_data = {
	.device_id = XUDC_DEVICE_ID_T186,
	.supply_names = tegra186_xudc_supply_names,
	.num_supplies = ARRAY_SIZE(tegra186_xudc_supply_names),
	.u1_enable = true,
	.u2_enable = true,
	.lpm_enable = false,
	.invalid_seq_num = false,
	.pls_quirk = false,
	.port_reset_quirk = false,
	.port_speed_quirk = false,
};

static struct tegra_xudc_soc_data tegra194_xudc_soc_data = {
	.device_id = XUDC_DEVICE_ID_T194,
	.supply_names = tegra194_xudc_supply_names,
	.num_supplies = ARRAY_SIZE(tegra194_xudc_supply_names),
	.u1_enable = true,
	.u2_enable = true,
	.lpm_enable = true,
	.invalid_seq_num = false,
	.pls_quirk = false,
	.disable_elpg = false,
	.port_reset_quirk = false,
	.port_speed_quirk = true,
};

static struct of_device_id tegra_xudc_of_match[] = {
	{
		.compatible = "nvidia,tegra210-xudc",
		.data = &tegra210_xudc_soc_data
	},
	{
		.compatible = "nvidia,tegra210b01-xudc",
		.data = &tegra210b01_xudc_soc_data
	},
	{
		.compatible = "nvidia,tegra186-xudc",
		.data = &tegra186_xudc_soc_data
	},
	{
		.compatible = "nvidia,tegra194-xudc",
		.data = &tegra194_xudc_soc_data
	},
	{ }
};
MODULE_DEVICE_TABLE(of, tegra_xudc_of_match);

static int tegra_xudc_init_extcon(struct tegra_xudc *xudc)
{
	char name[] = "vbus0";
	int i, count;

	count = of_count_phandle_with_args(xudc->dev->of_node,
			"extcon-cables", "#extcon-cells");
	if (count <= 0)
		return -ENODEV;

	for (i = 0; i < count; i++) {
		struct extcon_dev *edev;

		if (i == 0)
			strcpy(name, "vbus");
		else
			snprintf(name, sizeof(name), "vbus%d", i);

		edev = extcon_get_extcon_dev_by_cable(xudc->dev, name);
		if (IS_ERR(edev))
			return PTR_ERR(edev);
		xudc->data_role_extcons[i] = edev;
	}
	xudc->dev_mode_num = count;
	dev_info(xudc->dev, "device count: %d\n", xudc->dev_mode_num);

	return 0;
}

static void tegra_xudc_update_extcon(struct tegra_xudc *xudc)
{
	int i;
	int active = xudc->device_active;
	int orig_active = xudc->device_active;
	struct extcon_dev *edev;
	unsigned int vbus_state = 0;

	/* get vbus states */
	for (i = 0; i < xudc->dev_mode_num; i++) {
		edev = xudc->data_role_extcons[i];
		if (extcon_get_cable_state_(edev, EXTCON_USB))
			vbus_state |= BIT(i);
	}
	dev_info(xudc->dev, "vbus state: %x\n", vbus_state);

	/* handle vbus off */
	if (active && (vbus_state & BIT(active - 1)) == 0) {
		tegra_xudc_update_data_role(xudc, active - 1);
		active = 0;
	}

	/* handle vbus on */
	if (!active && vbus_state) {
		for (i = 0; i < xudc->dev_mode_num; i++) {
			if (vbus_state & BIT(i)) {
				tegra_xudc_update_data_role(xudc, i);
				break;
			}
		}
	}

	if (orig_active != xudc->device_active)
		dev_info(xudc->dev, "active: %d => %d\n", orig_active,
			xudc->device_active);
}

static int tegra_xudc_phy_get(struct tegra_xudc *xudc)
{
	int err, i, num;

	num = tegra_xusb_padctl_get_vbus_id_num(xudc->padctl);
	for (i = 0; i < num; i++) {
		char phy_name[] = "usb.-.";
		int usb2_port, usb3_port;

		tegra_xusb_padctl_get_vbus_id_ports(xudc->padctl, i,
				&usb2_port, &usb3_port);

		/* init usb3 phy */
		snprintf(phy_name, sizeof(phy_name),
			num != 1 ? "usb3-%d" : "usb3", usb3_port);
		xudc->usb3_phy[i] = devm_phy_optional_get(xudc->dev, phy_name);
		if (IS_ERR(xudc->usb3_phy[i])) {
			err = PTR_ERR(xudc->usb3_phy[i]);
			if (err == -EPROBE_DEFER)
				dev_info(xudc->dev,
					"usb3 phy is not available yet\n");
			else
				dev_err(xudc->dev,
					"failed to get usb3 phy %d\n", err);
			goto clean_up;
		}

		/* init usb2 phy */
		snprintf(phy_name, sizeof(phy_name),
			num != 1 ? "usb2-%d" : "usb2", usb2_port);
		xudc->utmi_phy[i] = devm_phy_optional_get(xudc->dev, phy_name);
		if (IS_ERR(xudc->utmi_phy[i])) {
			err = PTR_ERR(xudc->utmi_phy[i]);
			if (err == -EPROBE_DEFER)
				dev_info(xudc->dev,
					"usb2 phy is not available yet\n");
			else
				dev_err(xudc->dev,
					"failed to get usb2 phy %d\n", err);
			goto clean_up;
		}
	}

	return 0;

clean_up:
	for (i = 0; i < num; i++) {
		xudc->usb3_phy[i] = NULL;
		xudc->utmi_phy[i] = NULL;
	}

	return err;
}

static int tegra_xudc_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	struct tegra_xudc *xudc;
	struct resource *res;
	unsigned int i;
	int err;
	int partition_id_xusba, partition_id_xusbb;
	struct device_node *np;
	struct platform_device *cd_pdev;

	xudc = devm_kzalloc(&pdev->dev, sizeof(*xudc), GFP_ATOMIC);
	if (!xudc)
		return -ENOMEM;
	xudc->dev = &pdev->dev;
	platform_set_drvdata(pdev, xudc);

	match = of_match_device(tegra_xudc_of_match, &pdev->dev);
	if (!match)
		return -ENODEV;
	xudc->soc = match->data;

	/* set module parameter default values from soc data */
	u1_enable = xudc->soc->u1_enable;
	u2_enable = xudc->soc->u2_enable;
	lpm_enable = xudc->soc->lpm_enable;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(xudc->dev, "failed to get mem resource 0\n");
		return -ENXIO;
	}
	xudc->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(xudc->base))
		return PTR_ERR(xudc->base);
	xudc->phys_base = res->start;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(xudc->dev, "failed to get mem resource 1\n");
		return -ENXIO;
	}
	xudc->fpci = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(xudc->fpci))
		return PTR_ERR(xudc->fpci);

	if (XUDC_IS_T210(xudc)) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
		if (!res) {
			dev_err(xudc->dev, "failed to get mem resource 2\n");
			return -ENXIO;
		}
		xudc->ipfs = devm_ioremap_resource(&pdev->dev, res);
		if (IS_ERR(xudc->ipfs))
			return PTR_ERR(xudc->ipfs);
	}

	xudc->irq = platform_get_irq(pdev, 0);
	if (xudc->irq < 0) {
		dev_err(xudc->dev, "failed to get irq resource 0: %d\n",
				xudc->irq);
		return xudc->irq;
	}
	err = devm_request_irq(&pdev->dev, xudc->irq, tegra_xudc_irq, 0,
			       dev_name(&pdev->dev), xudc);
	if (err < 0) {
		dev_err(xudc->dev, "failed to claim irq %d\n", err);
		return err;
	}

	err = tegra_xudc_clk_init(xudc);
	if (err < 0) {
		dev_err(xudc->dev, "failed to init clocks %d\n", err);
		return err;
	}

	if (tegra_platform_is_silicon()) {
		xudc->supplies = devm_kcalloc(&pdev->dev,
				xudc->soc->num_supplies,
				sizeof(*xudc->supplies), GFP_KERNEL);
		if (!xudc->supplies)
			return -ENOMEM;
		for (i = 0; i < xudc->soc->num_supplies; i++)
			xudc->supplies[i].supply = xudc->soc->supply_names[i];
		err = devm_regulator_bulk_get(&pdev->dev,
				xudc->soc->num_supplies, xudc->supplies);
		if (err) {
			dev_err(xudc->dev, "failed to request regulators %d\n",
				err);
			return err;
		}
	}

	xudc->padctl = tegra_xusb_padctl_get(&pdev->dev);
	if (IS_ERR(xudc->padctl))
		return PTR_ERR(xudc->padctl);

	if (tegra_platform_is_silicon()) {
		err = regulator_bulk_enable(xudc->soc->num_supplies,
						xudc->supplies);
		if (err) {
			dev_err(xudc->dev, "failed to enable regulators %d\n",
				err);
			goto put_padctl;
		}
	}

	err = tegra_xudc_phy_get(xudc);
	if (err)
		goto disable_regulator;

	xudc->bwmgr = tegra_bwmgr_register(TEGRA_BWMGR_CLIENT_USBD);
	if (!xudc->bwmgr)
		dev_err(xudc->dev, "Failed to get bwmgr\n");

	err = of_property_read_u32(xudc->dev->of_node, "emc-frequency",
					&xudc->emc_frequency_required);
	if (err) {
		dev_dbg(xudc->dev, "Error read emc freq, setting default\n");
		xudc->emc_frequency_required = XUDC_EMC_MAX_FREQ;
	}
	dev_dbg(xudc->dev, "EMC frequency: %x\n", xudc->emc_frequency_required);
	xudc->emc_frequency_boosted = false;
	xudc->restore_work_scheduled = false;

	err = of_property_read_u32(pdev->dev.of_node, "nvidia,boost_cpu_freq",
						&xudc->boost_cpu_freq);
	if (err)
		dev_dbg(xudc->dev, "PMQOS CPU boost disabled\n");

	if (xudc->boost_cpu_freq > 0) {
		dev_info(xudc->dev, "PMQOS CPU boost enabled\n");
		xudc->cpu_boost_enabled = true;
	}

#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
	partition_id_xusba = tegra_pd_get_powergate_id(tegra_xusba_pd);
	partition_id_xusbb = tegra_pd_get_powergate_id(tegra_xusbb_pd);
#else
	partition_id_xusba = TEGRA_POWERGATE_XUSBA;
	partition_id_xusbb = TEGRA_POWERGATE_XUSBB;
#endif

	if (tegra_platform_is_silicon()) {

		err = tegra_xudc_init_extcon(xudc);
		if (err) {
			if (err != -EPROBE_DEFER)
				dev_err(xudc->dev,
				"extcon_get_extcon_dev_by_cable failed %d\n",
				err);
			goto disable_regulator;
		}
	}

	err = tegra_xudc_clk_enable(xudc);
	if (err < 0)
		goto disable_regulator;

	if (partition_id_xusba < 0) {
		err = -EINVAL;
		goto disable_clk;
	}
	err = tegra_unpowergate_partition(partition_id_xusba);
	if (err < 0) {
		dev_err(xudc->dev, "failed to unpowergate XUSBA partition\n");
		goto disable_clk;
	}

	if (partition_id_xusbb < 0) {
		err = -EINVAL;
		goto powergate_xusba;
	}
	err = tegra_unpowergate_partition(partition_id_xusbb);
	if (err < 0) {
		dev_err(xudc->dev, "failed to unpowergate XUSBB partition\n");
		goto powergate_xusba;
	}

	err = tegra_xudc_phy_init(xudc);
	if (err)
		goto powergate_xusbb;

	tegra_xudc_fpci_ipfs_init(xudc);
	tegra_xudc_device_params_init(xudc);

	err = tegra_xudc_alloc_event_ring(xudc);
	if (err)
		goto disable_phy;
	tegra_xudc_init_event_ring(xudc);

	err = tegra_xudc_alloc_eps(xudc);
	if (err)
		goto free_event_ring;
	tegra_xudc_init_eps(xudc);

	spin_lock_init(&xudc->lock);

	xudc->gadget.ops = &tegra_xudc_gadget_ops;
	xudc->gadget.ep0 = &xudc->ep[0].usb_ep;
	xudc->gadget.name = "tegra-xudc";
	xudc->gadget.max_speed = USB_SPEED_SUPER;

	err = usb_add_gadget_udc(&pdev->dev, &xudc->gadget);
	if (err) {
		dev_err(&pdev->dev, "failed to usb_add_gadget_udc\n");
		goto free_eps;
	}

	/* get charger detector */
	np = of_parse_phandle(pdev->dev.of_node, "charger-detector", 0);
	if (np) {
		cd_pdev = of_find_device_by_node(np);
		of_node_put(np);
		xudc->ucd = tegra_usb_get_ucd(cd_pdev);

		if (IS_ERR(xudc->ucd)) {
			dev_info(xudc->dev, "USB charger detection disabled\n");
			xudc->ucd = NULL;
		} else {
			xudc->current_ma = USB_ANDROID_SUSPEND_CURRENT_MA;
			xudc->connect_type = EXTCON_NONE;
			INIT_WORK(&xudc->set_charging_current_work,
				  tegra_xudc_set_charging_current_work);
			INIT_DELAYED_WORK(&xudc->non_std_charger_work,
					  tegra_xudc_non_std_charger_work);
			xudc->connect_type = EXTCON_NONE;
		}
	}

	init_completion(&xudc->disconnect_complete);

	if (tegra_platform_is_silicon()) {
		INIT_WORK(&xudc->data_role_work, tegra_xudc_data_role_work);
		xudc->data_role_nb.notifier_call =
				tegra_xudc_data_role_notifier;
		for (i = 0; i < xudc->dev_mode_num; i++) {
			extcon_register_notifier(xudc->data_role_extcons[i],
				EXTCON_USB, &xudc->data_role_nb);
		}
	}

	INIT_DELAYED_WORK(&xudc->plc_reset_work, tegra_xudc_plc_reset_work);

	wakeup_source_init(&lock.wakelock, "vbus-wakelock");

	tegra_xudc_update_extcon(xudc);
	INIT_DELAYED_WORK(&xudc->restore_emc, tegra_xudc_restore_emc_work);
	INIT_WORK(&xudc->boost_emc, tegra_xudc_boost_emc_work);
	INIT_DELAYED_WORK(&xudc->port_reset_war_work,
				tegra_xudc_port_reset_war_work);
	INIT_WORK(&xudc->pullup_work, tegra_xudc_gadget_pullup_work);

	tegra_pd_add_device(&pdev->dev);
	pm_runtime_set_active(&pdev->dev);
	pm_runtime_enable(&pdev->dev);

	if (tegra_platform_is_fpga())
		tegra_fpga_hack_init(xudc);

	if (xudc->cpu_boost_enabled) {
		dev_info(xudc->dev, "Initialize boost_cpufreq work\n");
		tegra_xudc_boost_cpu_init(xudc);
	}

	return 0;

free_eps:
	tegra_xudc_free_eps(xudc);
free_event_ring:
	tegra_xudc_free_event_ring(xudc);
disable_phy:
	tegra_xudc_phy_exit(xudc);
powergate_xusbb:
	tegra_powergate_partition(partition_id_xusbb);
powergate_xusba:
	tegra_powergate_partition(partition_id_xusba);
disable_clk:
	tegra_xudc_clk_disable(xudc);
disable_regulator:
	if (tegra_platform_is_silicon())
		regulator_bulk_disable(xudc->soc->num_supplies, xudc->supplies);
put_padctl:
	tegra_xusb_padctl_put(xudc->padctl);
	tegra_xudc_clk_deinit(xudc);

	return err;
}

static int tegra_xudc_remove(struct platform_device *pdev)
{
	int i;
	struct tegra_xudc *xudc = platform_get_drvdata(pdev);
	int partition_id_xusba, partition_id_xusbb;

	pm_runtime_get_sync(xudc->dev);

	if (xudc->ucd) {
		cancel_work_sync(&xudc->set_charging_current_work);
		cancel_delayed_work_sync(&xudc->non_std_charger_work);
		cancel_work_sync(&xudc->pullup_work);
		tegra_usb_release_ucd(xudc->ucd);
	}

	cancel_delayed_work(&xudc->plc_reset_work);
	for (i = 0; i < xudc->dev_mode_num; i++) {
		extcon_unregister_notifier(xudc->data_role_extcons[i],
			EXTCON_USB, &xudc->data_role_nb);
	}
	cancel_work_sync(&xudc->data_role_work);

	if (xudc->bwmgr)
		tegra_bwmgr_unregister(xudc->bwmgr);

	if (xudc->cpu_boost_enabled)
		tegra_xudc_boost_cpu_deinit(xudc);

	usb_del_gadget_udc(&xudc->gadget);
	tegra_xudc_free_eps(xudc);
	tegra_xudc_free_event_ring(xudc);

#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
	partition_id_xusbb = tegra_pd_get_powergate_id(tegra_xusbb_pd);
#else
	partition_id_xusbb = TEGRA_POWERGATE_XUSBB;
#endif
	if (partition_id_xusbb < 0)
		return -EINVAL;
#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
	partition_id_xusba = tegra_pd_get_powergate_id(tegra_xusba_pd);
#else
	partition_id_xusba = TEGRA_POWERGATE_XUSBA;
#endif
	if (partition_id_xusba < 0)
		return -EINVAL;
	tegra_powergate_partition(partition_id_xusbb);
	tegra_powergate_partition(partition_id_xusba);

	if (tegra_platform_is_silicon())
		regulator_bulk_disable(xudc->soc->num_supplies, xudc->supplies);

	for (i = 0; i < xudc->dev_mode_num; i++) {
		phy_power_off(xudc->utmi_phy[i]);
		phy_power_off(xudc->usb3_phy[i]);
	}
	tegra_xudc_phy_exit(xudc);
	pm_runtime_disable(xudc->dev);
	pm_runtime_put(xudc->dev);
	tegra_xudc_clk_deinit(xudc);

	tegra_xusb_padctl_put(xudc->padctl);
	wakeup_source_trash(&lock.wakelock);

	return 0;
}

#if IS_ENABLED(CONFIG_PM_SLEEP) || IS_ENABLED(CONFIG_PM)
static int tegra_xudc_powergate(struct tegra_xudc *xudc)
{
	unsigned long flags;
	int partition_id;

	if (xudc->soc->disable_elpg)
		return 0;

	dev_info(xudc->dev, "entering ELPG\n");
	spin_lock_irqsave(&xudc->lock, flags);
	xudc->powergated = true;
	xudc->saved_regs.ctrl = xudc_readl(xudc, CTRL);
	xudc->saved_regs.portpm = xudc_readl(xudc, PORTPM);
	xudc_writel(xudc, 0, CTRL);
	spin_unlock_irqrestore(&xudc->lock, flags);

	tegra_xudc_clk_disable(xudc);

#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
	partition_id = tegra_pd_get_powergate_id(tegra_xusba_pd);
#else
	partition_id = TEGRA_POWERGATE_XUSBA;
#endif
	if (partition_id < 0)
		return -EINVAL;
	tegra_powergate_partition(partition_id);
#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
	partition_id = tegra_pd_get_powergate_id(tegra_xusbb_pd);
#else
	partition_id = TEGRA_POWERGATE_XUSBB;
#endif
	if (partition_id < 0)
		return -EINVAL;
	tegra_powergate_partition(partition_id);

	if (tegra_platform_is_silicon())
		regulator_bulk_disable(xudc->soc->num_supplies, xudc->supplies);

	dev_info(xudc->dev, "entering ELPG done\n");
	return 0;
}

static int tegra_xudc_unpowergate(struct tegra_xudc *xudc)
{
	unsigned long flags;
	int err;
	int partition_id;

	if (xudc->soc->disable_elpg)
		return 0;

	dev_info(xudc->dev, "exiting ELPG\n");

	if (tegra_platform_is_silicon()) {
		err = regulator_bulk_enable(xudc->soc->num_supplies,
				xudc->supplies);
		if (err < 0)
			return err;
	}

	tegra_xudc_clk_enable(xudc);

#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
	partition_id = tegra_pd_get_powergate_id(tegra_xusbb_pd);
#else
	partition_id = TEGRA_POWERGATE_XUSBB;
#endif
	if (partition_id < 0)
		return -EINVAL;
	err = tegra_unpowergate_partition(partition_id);
	if (err < 0)
		return err;
#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
	partition_id = tegra_pd_get_powergate_id(tegra_xusba_pd);
#else
	partition_id = TEGRA_POWERGATE_XUSBA;
#endif
	if (partition_id < 0)
		return -EINVAL;
	err = tegra_unpowergate_partition(partition_id);
	if (err < 0)
		return err;

	tegra_xudc_fpci_ipfs_init(xudc);
	tegra_xudc_device_params_init(xudc);

	tegra_xudc_init_event_ring(xudc);
	tegra_xudc_init_eps(xudc);

	xudc_writel(xudc, xudc->saved_regs.portpm, PORTPM);
	xudc_writel(xudc, xudc->saved_regs.ctrl, CTRL);

	spin_lock_irqsave(&xudc->lock, flags);
	xudc->powergated = false;
	spin_unlock_irqrestore(&xudc->lock, flags);

	dev_info(xudc->dev, "exiting ELPG done\n");
	return 0;
}
#endif

#ifdef CONFIG_PM_SLEEP
static int tegra_xudc_suspend(struct device *dev)
{
	struct tegra_xudc *xudc = dev_get_drvdata(dev);
	unsigned long flags;

	spin_lock_irqsave(&xudc->lock, flags);
	xudc->suspended = true;
	spin_unlock_irqrestore(&xudc->lock, flags);

	flush_work(&xudc->data_role_work);

	/* Forcibly disconnect before powergating. */
	if (xudc->device_active) {
		tegra_xudc_device_mode_off(xudc, xudc->device_active - 1);
		xudc->device_active = 0;
	}

	if (!pm_runtime_status_suspended(dev))
		tegra_xudc_powergate(xudc);

	pm_runtime_disable(dev);

	return 0;
}

static int tegra_xudc_resume(struct device *dev)
{
	struct tegra_xudc *xudc = dev_get_drvdata(dev);
	unsigned long flags;
	int err;

	err = tegra_xudc_unpowergate(xudc);
	if (err < 0)
		return err;

	spin_lock_irqsave(&xudc->lock, flags);
	xudc->suspended = false;
	spin_unlock_irqrestore(&xudc->lock, flags);

	tegra_xudc_update_extcon(xudc);

	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	return 0;
}
#endif

#ifdef CONFIG_PM
static int tegra_xudc_runtime_suspend(struct device *dev)
{
	struct tegra_xudc *xudc = dev_get_drvdata(dev);
	unsigned long flags;

	spin_lock_irqsave(&xudc->lock, flags);
	if (WARN_ON(xudc->device_mode)) {
		spin_unlock_irqrestore(&xudc->lock, flags);
		return -EBUSY;
	}
	spin_unlock_irqrestore(&xudc->lock, flags);

	return tegra_xudc_powergate(xudc);
}

static int tegra_xudc_runtime_resume(struct device *dev)
{
	struct tegra_xudc *xudc = dev_get_drvdata(dev);

	return tegra_xudc_unpowergate(xudc);
}
#endif

static const struct dev_pm_ops tegra_xudc_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(tegra_xudc_suspend, tegra_xudc_resume)
	SET_RUNTIME_PM_OPS(tegra_xudc_runtime_suspend,
			   tegra_xudc_runtime_resume, NULL)
};

static struct platform_driver tegra_xudc_driver = {
	.probe = tegra_xudc_probe,
	.remove = tegra_xudc_remove,
	.driver = {
		.name = "tegra-xudc-new",
		.pm = &tegra_xudc_pm_ops,
		.of_match_table = tegra_xudc_of_match,
	},
};
module_platform_driver(tegra_xudc_driver);

static int set_vbus_wakelock(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_bool(val, kp);
	unsigned long flags;

	if (rv)
		return rv;

	/* release wakelock if held */
	if (!*(bool *)kp->arg) {
		spin_lock_irqsave(&wl_spinlock, flags);
		vbus_drop_wl(&lock);
		spin_unlock_irqrestore(&wl_spinlock, flags);
	}

	return 0;
}

static struct kernel_param_ops vbus_wakelock_param_ops = {
	.set = set_vbus_wakelock,
	.get = param_get_bool,
};

module_param_cb(vbus_wakelock, &vbus_wakelock_param_ops, &vbus_wakelock, 0644);
MODULE_PARM_DESC(vbus_wakelock,
		 "enable wakelock when detected as USB downstream port");

MODULE_DESCRIPTION("NVIDIA Tegra XUSB Device Controller");
MODULE_AUTHOR("Andrew Bresticker <abrestic@chromium.org>");
MODULE_AUTHOR("Hui Fu");
MODULE_LICENSE("GPL v2");
