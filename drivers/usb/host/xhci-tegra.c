/*
 * NVIDIA Tegra xHCI host controller driver
 *
 * Copyright (c) 2014-2021, NVIDIA CORPORATION. All rights reserved.
 * Copyright (C) 2014 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/phy/phy.h>
#include <linux/phy/tegra/xusb.h>
#include <linux/platform_device.h>
#include <linux/usb/ch9.h>
#include <linux/pm.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/circ_buf.h>
#include <linux/extcon.h>
#include <linux/pm_qos.h>
#include <linux/tegra-ivc.h>

#include <linux/tegra_pm_domains.h>
#include <linux/tegra-powergate.h>
#include <soc/tegra/chip-id.h>
#include <linux/tegra-firmwares.h>
#include <linux/usb/quirks.h>

#include "xhci.h"
#include "../core/hub.h"

static bool en_hcd_reinit = false;
module_param(en_hcd_reinit, bool, 0644);
MODULE_PARM_DESC(en_hcd_reinit, "Enable hcd reinit when hc died");
static void xhci_reinit_work(struct work_struct *work);
static int tegra_xhci_hcd_reinit(struct usb_hcd *hcd);

static bool max_burst_war_enable = true;
module_param(max_burst_war_enable, bool, 0644);
MODULE_PARM_DESC(max_burst_war_enable, "Max burst WAR");

#define BLACKLIST_SIZE	100
static uint downgraded_usb3[BLACKLIST_SIZE];
static int downgraded_count;

/* S_IRUGO | S_IWUSR | S_IWGRP */
module_param_array(downgraded_usb3, uint, &downgraded_count, 0664);
MODULE_PARM_DESC(downgraded_usb3,
"Downgraded USB3 devices with idVendoridProduct,e.g., 0x11112222,0x33334444");

static LIST_HEAD(hub_downgraded_list);

#define TEGRA_XHCI_SS_HIGH_SPEED 120000000
#define TEGRA_XHCI_SS_LOW_SPEED   12000000

/* FPCI CFG registers */
#define XUSB_CFG_1				0x004
#define  XUSB_IO_SPACE_EN			BIT(0)
#define  XUSB_MEM_SPACE_EN			BIT(1)
#define  XUSB_BUS_MASTER_EN			BIT(2)
#define XUSB_CFG_4				0x010
#define  XUSB_BASE_ADDR_SHIFT			15
#define  XUSB_BASE_ADDR_MASK			0x1ffff
#define  XUSB_T194_BASE_ADDR_SHIFT		18
#define  XUSB_T194_BASE_ADDR_MASK		0x3fff

#define XUSB_CFG_16				0x040
#define XUSB_CFG_24				0x060
#define XUSB_CFG_AXI_CFG			0x0f8
#define XUSB_CFG_ARU_C11PAGESEL			0x404
#define  XUSB_HSP0				BIT(12)
#define XUSB_CFG_ARU_C11_CSBRANGE		0x41c
#define XUSB_CFG_ARU_CONTEXT			0x43c
#define XUSB_CFG_ARU_CONTEXT_HS_PLS		0x478
#define XUSB_CFG_ARU_CONTEXT_FS_PLS		0x47c
#define XUSB_CFG_ARU_CONTEXT_HSFS_SPEED		0x480
#define XUSB_CFG_ARU_CONTEXT_HSFS_PP		0x484
#define XUSB_CFG_ARU_FW_SCRATCH                 0x00000440
#define XUSB_CFG_HSPX_CORE_CTRL			0x600
#define  XUSB_HSIC_PLLCLK_VLD			BIT(24)
#define XUSB_CFG_CSB_BASE_ADDR			0x800

/* FPCI mailbox registers */
#define XUSB_CFG_ARU_MBOX_CMD			0x0e4
#define  MBOX_DEST_FALC				BIT(27)
#define  MBOX_DEST_PME				BIT(28)
#define  MBOX_DEST_SMI				BIT(29)
#define  MBOX_DEST_XHCI				BIT(30)
#define  MBOX_INT_EN				BIT(31)
#define XUSB_CFG_ARU_MBOX_DATA_IN		0x0e8
#define  CMD_DATA_SHIFT				0
#define  CMD_DATA_MASK				0xffffff
#define  CMD_TYPE_SHIFT				24
#define  CMD_TYPE_MASK				0xff
#define XUSB_CFG_ARU_MBOX_DATA_OUT		0x0ec
#define XUSB_CFG_ARU_MBOX_OWNER			0x0f0
#define  MBOX_OWNER_NONE			0
#define  MBOX_OWNER_FW				1
#define  MBOX_OWNER_SW				2
#define XUSB_CFG_ARU_SMI_INTR			0x428
#define  MBOX_SMI_INTR_FW_HANG			BIT(1)
#define  MBOX_SMI_INTR_EN			BIT(3)

#define XUSB_CFG_ARU_T194_MBOX_CMD		0x068
#define XUSB_CFG_ARU_T194_MBOX_DATA_IN		0x06c
#define XUSB_CFG_ARU_T194_MBOX_DATA_OUT		0x070
#define XUSB_CFG_ARU_T194_MBOX_OWNER		0x074

/* IPFS registers */
#define XUSB_HOST_MSI_BAR_SZ_0			0x0c0
#define XUSB_HOST_MSI_AXI_BAR_ST_0		0x0c4
#define XUSB_HOST_MSI_FPCI_BAR_ST_0		0x0c8
#define XUSB_HOST_MSI_VEC0_0			0x100
#define XUSB_HOST_MSI_EN_VEC0_0			0x140
#define XUSB_HOST_CONFIGURATION_0		0x180
#define  IPFS_EN_FPCI				BIT(0)
#define XUSB_HOST_FPCI_ERROR_MASKS_0		0x184
#define XUSB_HOST_INTR_MASK_0			0x188
#define  IPFS_IP_INT_MASK			BIT(16)
#define XUSB_HOST_IPFS_INTR_ENABLE_0		0x198
#define XUSB_HOST_UFPCI_CONFIG_0		0x19c
#define XUSB_HOST_CLKGATE_HYSTERESIS_0		0x1bc
#define XUSB_HOST_MCCIF_FIFOCTRL_0		0x1dc

#define CSB_PAGE_SELECT_MASK			0x7fffff
#define CSB_PAGE_SELECT_SHIFT			9
#define CSB_PAGE_OFFSET_MASK			0x1ff
#define CSB_PAGE_SELECT(addr)	((addr) >> (CSB_PAGE_SELECT_SHIFT) &	\
				 CSB_PAGE_SELECT_MASK)
#define CSB_PAGE_OFFSET(addr)	((addr) & CSB_PAGE_OFFSET_MASK)

/* Falcon CSB registers */
#define XUSB_FALC_CPUCTL			0x100
#define  CPUCTL_STARTCPU			BIT(1)
#define  CPUCTL_STATE_HALTED			BIT(4)
#define  CPUCTL_STATE_STOPPED			BIT(5)
#define XUSB_FALC_BOOTVEC			0x104
#define XUSB_FALC_DMACTL			0x10c
#define XUSB_FALC_IMFILLRNG1			0x154
#define  IMFILLRNG1_TAG_MASK			0xffff
#define  IMFILLRNG1_TAG_LO_SHIFT		0
#define  IMFILLRNG1_TAG_HI_SHIFT		16
#define XUSB_FALC_IMFILLCTL			0x158

/* MP CSB registers */
#define XUSB_CSB_MP_ILOAD_ATTR			0x101a00
#define XUSB_CSB_MP_ILOAD_BASE_LO		0x101a04
#define XUSB_CSB_MP_ILOAD_BASE_HI		0x101a08
#define XUSB_CSB_MP_L2IMEMOP_SIZE		0x101a10
#define  L2IMEMOP_SIZE_SRC_OFFSET_SHIFT		8
#define  L2IMEMOP_SIZE_SRC_OFFSET_MASK		0x3ff
#define  L2IMEMOP_SIZE_SRC_COUNT_SHIFT		24
#define  L2IMEMOP_SIZE_SRC_COUNT_MASK		0xff
#define XUSB_CSB_MP_L2IMEMOP_TRIG		0x101a14
#define  L2IMEMOP_ACTION_SHIFT			24
#define  L2IMEMOP_INVALIDATE_ALL		(0x40 << L2IMEMOP_ACTION_SHIFT)
#define  L2IMEMOP_LOAD_LOCKED_RESULT		(0x11 << L2IMEMOP_ACTION_SHIFT)
#define XUSB_CSB_MEMPOOL_L2IMEMOP_RESULT	0x00101A18
#define  L2IMEMOP_RESULT_VLD			(1 << 31)
#define XUSB_CSB_MP_APMAP			0x10181c
#define  APMAP_BOOTPATH				BIT(31)

#define IMEM_BLOCK_SIZE				256

/* firmware retry limit */
#define FW_RETRY_COUNT			(5)

/* device quirks */
#define QUIRK_FOR_SS_DEVICE				BIT(0)
#define QUIRK_FOR_HS_DEVICE				BIT(1)
#define QUIRK_FOR_FS_DEVICE				BIT(2)
#define QUIRK_FOR_LS_DEVICE				BIT(3)
#define QUIRK_FOR_USB2_DEVICE \
	(QUIRK_FOR_HS_DEVICE | QUIRK_FOR_FS_DEVICE | QUIRK_FOR_LS_DEVICE)

#define USB_DEVICE_USB3(vid, pid) \
	USB_DEVICE(vid, pid), \
	.driver_info = (QUIRK_FOR_USB2_DEVICE | QUIRK_FOR_SS_DEVICE),

#define USB_DEVICE_USB2(vid, pid) \
	USB_DEVICE(vid, pid), \
	.driver_info = QUIRK_FOR_USB2_DEVICE,

#define USB_DEVICE_SS(vid, pid) \
	USB_DEVICE(vid, pid), \
	.driver_info = QUIRK_FOR_SS_DEVICE,

#define USB_DEVICE_HS(vid, pid) \
	USB_DEVICE(vid, pid), \
	.driver_info = QUIRK_FOR_HS_DEVICE,

#define USB_DEVICE_FS(vid, pid) \
	USB_DEVICE(vid, pid), \
	.driver_info = QUIRK_FOR_FS_DEVICE,

#define USB_DEVICE_LS(vid, pid) \
	USB_DEVICE(vid, pid), \
	.driver_info = QUIRK_FOR_LS_DEVICE,

/* Device ID */
#define XHCI_DEVICE_ID_T124	0x0fa3
#define XHCI_DEVICE_ID_T210	0x0fad
#define XHCI_DEVICE_ID_T186	0x10e2
#define XHCI_DEVICE_ID_T194	0x10fe

#define XHCI_IS_T210(t) (t->soc ? \
        (t->soc->device_id == XHCI_DEVICE_ID_T210) : false)
#define XHCI_IS_T186(t) (t->soc ? \
        (t->soc->device_id == XHCI_DEVICE_ID_T186) : false)
#define XHCI_IS_T194(t) (t->soc ? \
        (t->soc->device_id == XHCI_DEVICE_ID_T194) : false)

/* default parameters for boosting CPU freq */
#define XHCI_BOOST_TIMEOUT		2000 /* 2 seconds */
#define XHCI_BOOST_TRIGGER_SIZE		4096 /* 4KB */

static struct usb_device_id disable_usb_persist_quirk_list[] = {
	/* Sandisk Extreme USB 3.0 pen drive, SuperSpeed */
	{ USB_DEVICE_SS(0x0781, 0x5580) },
	{ }  /* terminating entry must be last */
};

static int usb_match_speed(struct usb_device *udev,
			    const struct usb_device_id *id)
{
	if (!id)
		return 0;

	if ((id->driver_info & QUIRK_FOR_SS_DEVICE) &&
					udev->speed == USB_SPEED_SUPER)
		return 1;

	if ((id->driver_info & QUIRK_FOR_HS_DEVICE) &&
					udev->speed == USB_SPEED_HIGH)
		return 1;

	if ((id->driver_info & QUIRK_FOR_FS_DEVICE) &&
					udev->speed == USB_SPEED_FULL)
		return 1;

	if ((id->driver_info & QUIRK_FOR_LS_DEVICE) &&
					udev->speed == USB_SPEED_LOW)
		return 1;

	return 0;
}

#define FW_IOCTL_LOG_DEQUEUE_LOW        (4)
#define FW_IOCTL_LOG_DEQUEUE_HIGH       (5)
#define FW_IOCTL_DATA_SHIFT             (0)
#define FW_IOCTL_DATA_MASK              (0x00ffffff)
#define FW_IOCTL_TYPE_SHIFT             (24)
#define FW_IOCTL_TYPE_MASK              (0xff000000)
#define FW_LOG_SIZE                     ((int) sizeof(struct log_entry))
#define FW_LOG_COUNT                    (4096)
#define FW_LOG_RING_SIZE                (FW_LOG_SIZE * FW_LOG_COUNT)
#define FW_LOG_PAYLOAD_SIZE             (27)
#define DRIVER                          (0x01)
#define CIRC_BUF_SIZE                   (4 * (1 << 20)) /* 4MB */
#define FW_LOG_THREAD_RELAX             (msecs_to_jiffies(500))

/* tegra_xhci_firmware_log.flags bits */
#define FW_LOG_CONTEXT_VALID            (0)
#define FW_LOG_FILE_OPENED              (1)

#define FW_MAJOR_VERSION(x)             (((x) >> 24) & 0xff)
#define FW_MINOR_VERSION(x)             (((x) >> 16) & 0xff)

#define DEGRADED_PORT_COUNT		2

enum build_info_log {
	LOG_NONE = 0,
	LOG_MEMORY
};

struct tegra_xusb_fw_header {
	u32 boot_loadaddr_in_imem;
	u32 boot_codedfi_offset;
	u32 boot_codetag;
	u32 boot_codesize;
	u32 phys_memaddr;
	u16 reqphys_memsize;
	u16 alloc_phys_memsize;
	u32 rodata_img_offset;
	u32 rodata_section_start;
	u32 rodata_section_end;
	u32 main_fnaddr;
	u32 fwimg_cksum;
	u32 fwimg_created_time;
	u32 imem_resident_start;
	u32 imem_resident_end;
	u32 idirect_start;
	u32 idirect_end;
	u32 l2_imem_start;
	u32 l2_imem_end;
	u32 version_id;
	u8 init_ddirect;
	u8 reserved[3];
	u32 phys_addr_log_buffer;
	u32 total_log_entries;
	u32 dequeue_ptr;
	u32 dummy_var[2];
	u32 fwimg_len;
	u8 magic[8];
	u32 ss_low_power_entry_timeout;
	u8 num_hsic_port;
	u8 ss_portmap;
	u8 build_log:4;
	u8 build_type:4;
	u8 padding[137]; /* Pad to 256 bytes */
};

enum tegra_xhci_phy_type {
	USB3_PHY,
	USB2_PHY,
	HSIC_PHY,
	MAX_PHY_TYPES,
};

static const char * const tegra_xhci_phy_names[] = {
	[USB3_PHY] = "usb3",
	[USB2_PHY] = "usb2",
	[HSIC_PHY] = "hsic",
};

struct tegra_xusb_soc {
	u16 device_id;
	const char *firmware;
	const char * const *supply_names;
	unsigned int num_supplies;

	unsigned int num_typed_phys[MAX_PHY_TYPES];
	struct {
		struct {
			unsigned int offset;
			unsigned int count;
		} usb2, hsic, usb3;
	} ports;

	u32 cfg_4_addr_shift;
	u32 cfg_4_addr_mask;
	u32 cfg_aru_mbox_cmd;
	u32 cfg_aru_mbox_data_in;
	u32 cfg_aru_mbox_data_out;
	u32 cfg_aru_mbox_owner;

	bool scale_ss_clock;
	bool has_ipfs;
	bool ss_lfps_detector_war;

	bool is_xhci_vf;
	u8 vf_id;

	bool lpm_support;

	bool handle_oc;
	bool disable_hsic_wake;
	bool disable_elpg;
	bool otg_set_port_power;
};

struct tegra_xhci_ipfs_context {
	u32 msi_bar_sz;
	u32 msi_axi_barst;
	u32 msi_fpci_barst;
	u32 msi_vec0;
	u32 msi_en_vec0;
	u32 fpci_error_masks;
	u32 intr_mask;
	u32 ipfs_intr_enable;
	u32 ufpci_config;
	u32 clkgate_hysteresis;
	u32 xusb_host_mccif_fifo_cntrl;
};

struct tegra_xhci_fpci_context {
	u32 hs_pls;
	u32 fs_pls;
	u32 hsfs_speed;
	u32 hsfs_pp;
	u32 cfg_aru;
	u32 cfg_order;
	u32 cfg_fladj;
	u32 cfg_sid;
};

struct log_entry {
	u32 sequence_no;
	u8 data[FW_LOG_PAYLOAD_SIZE];
	u8 owner;
};

struct tegra_xhci_firmware_log {
	dma_addr_t phys_addr;           /* dma-able address */
	void *virt_addr;                /* kernel va of the shared log buffer */
	struct log_entry *dequeue;      /* current dequeue pointer (va) */
	struct circ_buf circ;           /* big circular buffer */
	u32 seq;                        /* log sequence number */

	struct task_struct *thread;     /* a thread to consume log */
	struct mutex mutex;
	wait_queue_head_t read_wait;
	wait_queue_head_t write_wait;
	wait_queue_head_t intr_wait;
	struct dentry *log_file;
	unsigned long flags;
};

struct xusb_otg_port {
	int usb2_otg_port_base_1; /* one based usb2 port number */
	int usb3_otg_port_base_1; /* one based usb3 port number */

	struct extcon_dev *edev;
	bool changed;
	bool host_mode;
	bool inited;
};

struct usb_downgraded_port {
	int portnum;
	u16 id_vendor;
	u16 id_product;
	char serial[31];
	struct list_head downgraded_list;
};

struct tegra_xusb {
	struct device *dev;
	void __iomem *regs;
	struct usb_hcd *hcd;

	struct mutex lock;

	int xhci_irq;
	int mbox_irq;
	int padctl_irq;

	void __iomem *ipfs_base;
	void __iomem *fpci_base;
	resource_size_t fpci_start;
	resource_size_t fpci_len;

	const struct tegra_xusb_soc *soc;

	struct regulator_bulk_data *supplies;

	struct tegra_xusb_padctl *padctl;

	struct clk *host_clk;
	struct clk *falcon_clk;
	struct clk *ss_clk;
	struct clk *ss_src_clk;
	struct clk *hs_src_clk;
	struct clk *fs_src_clk;
	struct clk *pll_u_480m;
	struct clk *clk_m;
	struct clk *pll_e;
	struct clk *core_superspeed_clk;
	struct clk *falcon_host_clk;
	struct clk *falcon_superspeed_clk;
	struct clk *fs_host_clk;
	bool clk_enabled;

	struct phy **phys;
	struct phy **typed_phys[MAX_PHY_TYPES];
	struct phy **cdp_ext_phys; /* external cdp phys */
	/* Used to store the port to phy mapping in the
	 * virtualization scenario
	 */
	int *port_phy_map;
	int *port_to_phy[MAX_PHY_TYPES];
	unsigned int num_phys;
	unsigned int num_hsic_port; /* count */

	/* Firmware loading related */
	struct delayed_work firmware_retry_work;
	int fw_retry_count;
	bool fw_loaded;
	struct {
		size_t size;
		void *virt;
		dma_addr_t phys;
	} fw;

	struct dentry *debugfs_dir;
	struct dentry *dump_ring_file;
	struct tegra_xhci_firmware_log log;

	int pgid_ss;
	int pgid_host;

	bool suspended;
	struct tegra_xhci_fpci_context fpci_ctx;
	struct tegra_xhci_ipfs_context ipfs_ctx;
	u32 enable_utmi_pad_after_lp0_exit;

	struct xusb_otg_port otg_ports[XUSB_MAX_OTG_PORT_NUM];
	int otg_port_num;

	struct notifier_block id_extcons_nb;
	struct work_struct id_extcons_work;

	u8 *connected_usb2_ports; /* keep track of connected UTMI ports */
	bool cdp_enabled;
	bool cdp_internal;

	struct work_struct oc_work;

	struct mutex boost_cpufreq_lock;
	struct pm_qos_request core_req;
	struct pm_qos_request boost_cpufreq_req;
	struct work_struct boost_cpufreq_work;
	unsigned int boost_cpu_freq;
	unsigned int boost_cpu_trigger;
	unsigned long cpufreq_last_boosted;
	bool cpu_boost_enabled;
	struct tegra_hv_ivc_cookie *ivck;
	char ivc_rx[128]; /* Buffer to receive pad ivc message */
	struct work_struct ivc_work;
	bool hsic_power_on;
	bool hsic_set_idle;
	bool xhci_err_init;
	struct usb_downgraded_port degraded_port[DEGRADED_PORT_COUNT];
	unsigned int downgrade_enabled;

	struct device *fwdev;
};

static struct hc_driver __read_mostly tegra_xhci_hc_driver;

#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
static const struct of_device_id tegra_xusba_pd[] = {
	{ .compatible = "nvidia,tegra194-xusba-pd", },
	{ .compatible = "nvidia,tegra186-xusba-pd", },
	{ .compatible = "nvidia,tegra210-xusba-pd", },
	{},
};

static const struct of_device_id tegra_xusbc_pd[] = {
	{ .compatible = "nvidia,tegra194-xusbc-pd", },
	{ .compatible = "nvidia,tegra186-xusbc-pd", },
	{ .compatible = "nvidia,tegra210-xusbc-pd", },
	{},
};
#endif

static inline struct tegra_xusb *hcd_to_tegra_xusb(struct usb_hcd *hcd)
{
	return (struct tegra_xusb *) dev_get_drvdata(hcd->self.controller);
}

static struct xusb_otg_port *find_otg_port(struct tegra_xusb *tegra,
				enum tegra_xhci_phy_type type, int index)
{
	int i;
	struct xusb_otg_port *port;

	for (i = 0; i < tegra->otg_port_num; i++) {

		port = &tegra->otg_ports[i];

		if ((type == USB2_PHY) &&
			(index != port->usb2_otg_port_base_1 - 1))
			continue;

		if ((type == USB3_PHY) &&
			(index != port->usb3_otg_port_base_1 - 1))
			continue;

		return port;
	}

	return NULL;
}

static bool is_otg_phy(struct tegra_xusb *tegra,
				enum tegra_xhci_phy_type type, int index)
{
	struct xusb_otg_port *otg_port;

	otg_port = find_otg_port(tegra, type, index);

	return otg_port != NULL;
}

static bool is_host_mode_phy(struct tegra_xusb *tegra,
				enum tegra_xhci_phy_type type, int index)
{
	struct xusb_otg_port *otg_port;

	if (!tegra->typed_phys[type][index])
		return false;

	if ((type == HSIC_PHY))
		return true;

	otg_port = find_otg_port(tegra, type, index);
	if (otg_port)
		return otg_port->host_mode;

	return true;
}

static void tegra_xusb_boost_cpu_freq_fn(struct work_struct *work)
{
	struct tegra_xusb *tegra = container_of(work, struct tegra_xusb,
							boost_cpufreq_work);
	unsigned long delay = XHCI_BOOST_TIMEOUT;
	s32 cpufreq = tegra->boost_cpu_freq * 1000;

	mutex_lock(&tegra->boost_cpufreq_lock);

	dev_dbg(tegra->dev, "boost cpu freq %d kHz, with timeout %lu ms\n",
							cpufreq, delay);

	if (XHCI_IS_T210(tegra))
		pm_qos_update_request_timeout(&tegra->core_req,
			PM_QOS_MAX_ONLINE_CPUS_DEFAULT_VALUE, delay * 1000);
	pm_qos_update_request_timeout(&tegra->boost_cpufreq_req,
					cpufreq, delay * 1000);

	tegra->cpufreq_last_boosted = jiffies;
	mutex_unlock(&tegra->boost_cpufreq_lock);
}

static void tegra_xusb_boost_cpu_init(struct tegra_xusb *tegra)
{
	INIT_WORK(&tegra->boost_cpufreq_work, tegra_xusb_boost_cpu_freq_fn);

	if (XHCI_IS_T210(tegra))
		pm_qos_add_request(&tegra->core_req, PM_QOS_MIN_ONLINE_CPUS,
							PM_QOS_DEFAULT_VALUE);
	pm_qos_add_request(&tegra->boost_cpufreq_req,
			PM_QOS_CPU_FREQ_MIN, PM_QOS_DEFAULT_VALUE);

	mutex_init(&tegra->boost_cpufreq_lock);
}

static void tegra_xusb_boost_cpu_deinit(struct tegra_xusb *tegra)
{
	cancel_work_sync(&tegra->boost_cpufreq_work);

	if (XHCI_IS_T210(tegra))
		pm_qos_remove_request(&tegra->core_req);
	pm_qos_remove_request(&tegra->boost_cpufreq_req);

	mutex_destroy(&tegra->boost_cpufreq_lock);
}

static ssize_t show_xhci_stats(struct device *dev,
		struct device_attribute *attr, char *buf) {
	struct tegra_xusb *tegra = NULL;
	struct xhci_hcd *xhci = NULL;
	ssize_t ret;

	if (dev != NULL)
		tegra = dev_get_drvdata(dev);

	if (tegra != NULL) {
		xhci = hcd_to_xhci(tegra->hcd);
		ret =  snprintf(buf, PAGE_SIZE, "comp_tx_err:%u\nversion:%u\n",
			xhci->xhci_ereport.comp_tx_err,
			xhci->xhci_ereport.version);
	} else
		ret = snprintf(buf, PAGE_SIZE, "comp_tx_err:0\nversion:0\n");

	return ret;
}

static DEVICE_ATTR(xhci_stats, 0444, show_xhci_stats, NULL);

/* sysfs node for fw check*/
static ssize_t fw_version_show(struct device *dev, char *buf, size_t size)
{
	struct tegra_xusb *tegra = dev_get_drvdata(dev);
	struct tegra_xusb_fw_header *header = NULL;
	time_t timestamp;
	struct tm fw_tm;

	if (!tegra)
		return scnprintf(buf, size, "device is not available\n");

	header = (struct tegra_xusb_fw_header *)tegra->fw.virt;

	timestamp = le32_to_cpu(header->fwimg_created_time);
	time_to_tm(timestamp, 0, &fw_tm);

	return scnprintf(buf, size,
			"Firmware timestamp: %ld-%02d-%02d %02d:%02d:%02d UTC, "
			"Version: %02x.%02x %s\n",
			fw_tm.tm_year + 1900,
			fw_tm.tm_mon + 1, fw_tm.tm_mday, fw_tm.tm_hour,
			fw_tm.tm_min, fw_tm.tm_sec,
			FW_MAJOR_VERSION(header->version_id),
			FW_MINOR_VERSION(header->version_id),
			(header->build_log == LOG_MEMORY) ?
			"debug" : "release");
}

static struct attribute *tegra_sysfs_entries_errs[] = {
	&dev_attr_xhci_stats.attr,
	NULL,
};

static struct attribute_group tegra_sysfs_group_errors = {
	.name = "xhci-stats",
	.attrs = tegra_sysfs_entries_errs,
};

static inline u32 fpci_readl(struct tegra_xusb *tegra, unsigned int offset)
{
	return readl(tegra->fpci_base + offset);
}

static inline void fpci_writel(struct tegra_xusb *tegra, u32 value,
			       unsigned int offset)
{
	writel(value, tegra->fpci_base + offset);
}

static inline u32 ipfs_readl(struct tegra_xusb *tegra, unsigned int offset)
{
	return readl(tegra->ipfs_base + offset);
}

static inline void ipfs_writel(struct tegra_xusb *tegra, u32 value,
			       unsigned int offset)
{
	writel(value, tegra->ipfs_base + offset);
}

static u32 csb_readl(struct tegra_xusb *tegra, unsigned int offset)
{
	u32 page = CSB_PAGE_SELECT(offset);
	u32 ofs = CSB_PAGE_OFFSET(offset);

	fpci_writel(tegra, page, XUSB_CFG_ARU_C11_CSBRANGE);

	return fpci_readl(tegra, XUSB_CFG_CSB_BASE_ADDR + ofs);
}

static void csb_writel(struct tegra_xusb *tegra, u32 value,
		       unsigned int offset)
{
	u32 page = CSB_PAGE_SELECT(offset);
	u32 ofs = CSB_PAGE_OFFSET(offset);

	fpci_writel(tegra, page, XUSB_CFG_ARU_C11_CSBRANGE);
	fpci_writel(tegra, value, XUSB_CFG_CSB_BASE_ADDR + ofs);
}

/**
 * fw_log_next - find next log entry in a tegra_xhci_firmware_log context.
 *      This function takes care of wrapping. That means when current log entry
 *      is the last one, it returns with the first one.
 *
 * @param log   The tegra_xhci_firmware_log context.
 * @param this  The current log entry.
 * @return      The log entry which is next to the current one.
 */
static inline struct log_entry *fw_log_next(
		struct tegra_xhci_firmware_log *log, struct log_entry *this)
{
	struct log_entry *first = (struct log_entry *) log->virt_addr;
	struct log_entry *last = first + FW_LOG_COUNT - 1;

	WARN((this < first) || (this > last), "%s: invalid input\n", __func__);

	return (this == last) ? first : (this + 1);
}

/**
 * fw_log_update_dequeue_pointer - update dequeue pointer to both firmware and
 *      tegra_xhci_firmware_log.dequeue.
 *
 * @param log   The tegra_xhci_firmware_log context.
 * @param n     Counts of log entries to fast-forward.
 */
static inline void fw_log_update_deq_pointer(
		struct tegra_xhci_firmware_log *log, int n)
{
	struct tegra_xusb *tegra =
			container_of(log, struct tegra_xusb, log);
	struct device *dev = tegra->dev;
	struct log_entry *deq = tegra->log.dequeue;
	dma_addr_t physical_addr;
	u32 reg;

	dev_vdbg(dev, "curr 0x%p fast-forward %d entries\n", deq, n);
	while (n-- > 0)
		deq = fw_log_next(log, deq);

	tegra->log.dequeue = deq;
	physical_addr = tegra->log.phys_addr +
			((u8 *)deq - (u8 *)tegra->log.virt_addr);

	/* update dequeue pointer to firmware */
	reg = (FW_IOCTL_LOG_DEQUEUE_LOW << FW_IOCTL_TYPE_SHIFT);
	reg |= (physical_addr & 0xffff); /* lower 16-bits */
	iowrite32(reg, tegra->fpci_base + XUSB_CFG_ARU_FW_SCRATCH);

	reg = (FW_IOCTL_LOG_DEQUEUE_HIGH << FW_IOCTL_TYPE_SHIFT);
	reg |= ((physical_addr >> 16) & 0xffff); /* higher 16-bits */
	iowrite32(reg, tegra->fpci_base + XUSB_CFG_ARU_FW_SCRATCH);

	dev_vdbg(dev, "new 0x%p physical addr 0x%x\n", deq, (u32)physical_addr);
}

static inline bool circ_buffer_full(struct circ_buf *circ)
{
	int space = CIRC_SPACE(circ->head, circ->tail, CIRC_BUF_SIZE);

	return (space <= FW_LOG_SIZE);
}

static inline bool fw_log_available(struct tegra_xusb *tegra)
{
	return (tegra->log.dequeue->owner == DRIVER);
}

/**
 * fw_log_wait_empty_timeout - wait firmware log thread to clean up shared
 *      log buffer.
 * @param tegra:        tegra_xusb context
 * @param msec:         timeout value in millisecond
 * @return true:        shared log buffer is empty,
 *         false:       shared log buffer isn't empty.
 */
static inline bool fw_log_wait_empty_timeout(struct tegra_xusb *tegra,
		unsigned timeout)
{
	unsigned long target = jiffies + msecs_to_jiffies(timeout);
	struct circ_buf *circ = &tegra->log.circ;
	bool ret;

	mutex_lock(&tegra->log.mutex);

	while (fw_log_available(tegra) && time_is_after_jiffies(target)) {
		if (circ_buffer_full(circ) &&
			!test_bit(FW_LOG_FILE_OPENED, &tegra->log.flags))
			break; /* buffer is full but nobody is reading log */

		mutex_unlock(&tegra->log.mutex);
		usleep_range(1000, 2000);
		mutex_lock(&tegra->log.mutex);
        }

	ret = fw_log_available(tegra);
	mutex_unlock(&tegra->log.mutex);

	return ret;
}

/**
 * fw_log_copy - copy firmware log from device's buffer to driver's circular
 *      buffer.
 * @param tegra tegra_xusb context
 * @return true,        We still have firmware log in device's buffer to copy.
 *                      This function returned due the driver's circular buffer
 *                      is full. Caller should invoke this function again as
 *                      soon as there is space in driver's circular buffer.
 *         false,       Device's buffer is empty.
 */
static inline bool fw_log_copy(struct tegra_xusb *tegra)
{
	struct device *dev = tegra->dev;
	struct circ_buf *circ = &tegra->log.circ;
	int head, tail;
	int buffer_len, copy_len;
	struct log_entry *entry;
	struct log_entry *first = tegra->log.virt_addr;

	while (fw_log_available(tegra)) {

		/* calculate maximum contiguous driver buffer length */
		head = circ->head;
		tail = ACCESS_ONCE(circ->tail);
		buffer_len = CIRC_SPACE_TO_END(head, tail, CIRC_BUF_SIZE);
		/* round down to FW_LOG_SIZE */
		buffer_len -= (buffer_len % FW_LOG_SIZE);
		if (!buffer_len)
			return true; /* log available but no space left */

		/* calculate maximum contiguous log copy length */
		entry = tegra->log.dequeue;
		copy_len = 0;
		do {
			if (tegra->log.seq != entry->sequence_no) {
				dev_warn(dev,
				"%s: discontinuous seq no, expect %u get %u\n",
				__func__, tegra->log.seq, entry->sequence_no);
			}
			tegra->log.seq = entry->sequence_no + 1;

			copy_len += FW_LOG_SIZE;
			buffer_len -= FW_LOG_SIZE;
			if (!buffer_len)
				break; /* no space left */
			entry = fw_log_next(&tegra->log, entry);
		} while ((entry->owner == DRIVER) && (entry != first));

		memcpy(&circ->buf[head], tegra->log.dequeue, copy_len);
		memset(tegra->log.dequeue, 0, copy_len);
		circ->head = (circ->head + copy_len) & (CIRC_BUF_SIZE - 1);

		mb(); /* make sure controller sees it */

		fw_log_update_deq_pointer(&tegra->log, copy_len/FW_LOG_SIZE);

		dev_vdbg(dev, "copied %d entries, new dequeue 0x%p\n",
				copy_len/FW_LOG_SIZE, tegra->log.dequeue);
		wake_up_interruptible(&tegra->log.read_wait);
	}

	return false;
}

static int fw_log_thread(void *data)
{
	struct tegra_xusb *tegra = data;
	struct device *dev = tegra->dev;
	struct circ_buf *circ = &tegra->log.circ;
	bool logs_left;

	dev_dbg(dev, "start firmware log thread\n");

	do {
		mutex_lock(&tegra->log.mutex);
		if (circ_buffer_full(circ)) {
			mutex_unlock(&tegra->log.mutex);
			dev_info(dev, "%s: circ buffer full\n", __func__);
			wait_event_interruptible(tegra->log.write_wait,
				kthread_should_stop() || !circ_buffer_full(circ));
			mutex_lock(&tegra->log.mutex);
		}

		logs_left = fw_log_copy(tegra);
		mutex_unlock(&tegra->log.mutex);

		/* relax if no logs left  */
		if (!logs_left)
			wait_event_interruptible_timeout(tegra->log.intr_wait,
				fw_log_available(tegra), FW_LOG_THREAD_RELAX);
	} while (!kthread_should_stop());

	dev_dbg(dev, "stop firmware log thread\n");
	return 0;
}

static inline bool circ_buffer_empty(struct circ_buf *circ)
{
	return (CIRC_CNT(circ->head, circ->tail, CIRC_BUF_SIZE) == 0);
}

static ssize_t fw_log_file_read(struct file *file, char __user *buf,
		size_t count, loff_t *offp)
{
	struct tegra_xusb *tegra = file->private_data;
	struct device *dev = tegra->dev;
	struct circ_buf *circ = &tegra->log.circ;
	int head, tail;
	size_t n = 0;
	int s;

	mutex_lock(&tegra->log.mutex);

	while (circ_buffer_empty(circ)) {
		mutex_unlock(&tegra->log.mutex);
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN; /* non-blocking read */

		dev_dbg(dev, "%s: nothing to read\n", __func__);

		if (wait_event_interruptible(tegra->log.read_wait,
				!circ_buffer_empty(circ)))
			return -ERESTARTSYS;

		if (mutex_lock_interruptible(&tegra->log.mutex))
			return -ERESTARTSYS;
	}

	while (count > 0) {
		head = ACCESS_ONCE(circ->head);
		tail = circ->tail;
		s = min_t(int, count,
				CIRC_CNT_TO_END(head, tail, CIRC_BUF_SIZE));

		if (s > 0) {
			if (copy_to_user(&buf[n], &circ->buf[tail], s)) {
				dev_warn(dev, "copy_to_user failed\n");
				mutex_unlock(&tegra->log.mutex);
				return -EFAULT;
			}
			circ->tail = (circ->tail + s) & (CIRC_BUF_SIZE - 1);

			count -= s;
			n += s;
		} else
			break;
	}

	mutex_unlock(&tegra->log.mutex);

	wake_up_interruptible(&tegra->log.write_wait);

	dev_dbg(dev, "%s: %zu bytes\n", __func__, n);

	return n;
}

static int fw_log_file_open(struct inode *inode, struct file *file)
{
	struct tegra_xusb *tegra;

	file->private_data = inode->i_private;
	tegra = file->private_data;

	if (test_and_set_bit(FW_LOG_FILE_OPENED, &tegra->log.flags)) {
		dev_info(tegra->dev, "%s: already opened\n", __func__);
		return -EBUSY;
	}

	return 0;
}

static int fw_log_file_close(struct inode *inode, struct file *file)
{
	struct tegra_xusb *tegra = file->private_data;

	clear_bit(FW_LOG_FILE_OPENED, &tegra->log.flags);

	return 0;
}

static const struct file_operations firmware_log_fops = {
		.open           = fw_log_file_open,
		.release        = fw_log_file_close,
		.read           = fw_log_file_read,
		.owner          = THIS_MODULE,
};

#ifdef CONFIG_USB_XHCI_HCD_DEBUGGING
static ssize_t dump_ring_file_write(struct file *file, const char __user *buf,
	size_t count, loff_t *offp)
{
	struct tegra_xusb *tegra = file->private_data;
	struct xhci_hcd *xhci = hcd_to_xhci(tegra->hcd);

	/* trigger xhci_event_ring_work() for debug */
	del_timer_sync(&xhci->event_ring_timer);
	xhci->event_ring_timer.expires = jiffies;
	add_timer(&xhci->event_ring_timer);

	return count;
}

static const struct file_operations dump_ring_fops = {
		.write          = dump_ring_file_write,
		.owner          = THIS_MODULE,
};
#endif

static int fw_log_init(struct tegra_xusb *tegra)
{
	struct device *dev = tegra->dev;
	int rc = 0;

	if (!tegra->debugfs_dir)
		return -ENODEV; /* no debugfs support */

	if (test_bit(FW_LOG_CONTEXT_VALID, &tegra->log.flags))
		return 0; /* already done */

	/* allocate buffer to be shared between driver and firmware */
	tegra->log.virt_addr = dma_alloc_coherent(dev,
			FW_LOG_RING_SIZE, &tegra->log.phys_addr, GFP_KERNEL);

	if (!tegra->log.virt_addr) {
		dev_err(dev, "dma_alloc_coherent() size %d failed\n",
				FW_LOG_RING_SIZE);
		return -ENOMEM;
	}

	dev_info(dev, "%d bytes log buffer physical 0x%u virtual 0x%p\n",
		FW_LOG_RING_SIZE, (u32)tegra->log.phys_addr,
		tegra->log.virt_addr);

	memset(tegra->log.virt_addr, 0, FW_LOG_RING_SIZE);
	tegra->log.dequeue = tegra->log.virt_addr;

	tegra->log.circ.buf = vmalloc(CIRC_BUF_SIZE);
	if (!tegra->log.circ.buf) {
		rc = -ENOMEM;
		goto error_free_dma;
	}

	tegra->log.circ.head = 0;
	tegra->log.circ.tail = 0;

	init_waitqueue_head(&tegra->log.read_wait);
	init_waitqueue_head(&tegra->log.write_wait);
	init_waitqueue_head(&tegra->log.intr_wait);

	mutex_init(&tegra->log.mutex);

	tegra->log.log_file = debugfs_create_file("firmware_log", S_IRUGO,
			tegra->debugfs_dir, tegra, &firmware_log_fops);
	if ((!tegra->log.log_file) ||
			(tegra->log.log_file == ERR_PTR(-ENODEV))) {
		dev_warn(dev, "debugfs_create_file() failed\n");
		rc = -ENOMEM;
		goto error_free_mem;
	}

	tegra->log.thread = kthread_run(fw_log_thread, tegra, "xusb-fw-log");
	if (IS_ERR(tegra->log.thread)) {
		dev_warn(dev, "kthread_run() failed\n");
		rc = -ENOMEM;
		goto error_remove_debugfs_file;
	}

	set_bit(FW_LOG_CONTEXT_VALID, &tegra->log.flags);
	return rc;

error_remove_debugfs_file:
	debugfs_remove(tegra->log.log_file);
error_free_mem:
	vfree(tegra->log.circ.buf);
error_free_dma:
	dma_free_coherent(dev, FW_LOG_RING_SIZE,
			tegra->log.virt_addr, tegra->log.phys_addr);
	memset(&tegra->log, 0, sizeof(tegra->log));
	return rc;
}

static void fw_log_deinit(struct tegra_xusb *tegra)
{
	struct device *dev = tegra->dev;

	if (test_and_clear_bit(FW_LOG_CONTEXT_VALID, &tegra->log.flags)) {

		debugfs_remove(tegra->log.log_file);

		wake_up_interruptible(&tegra->log.read_wait);
		wake_up_interruptible(&tegra->log.write_wait);
		kthread_stop(tegra->log.thread);

		mutex_lock(&tegra->log.mutex);
		dma_free_coherent(dev, FW_LOG_RING_SIZE,
			tegra->log.virt_addr, tegra->log.phys_addr);
		vfree(tegra->log.circ.buf);
		tegra->log.circ.head = tegra->log.circ.tail = 0;
		mutex_unlock(&tegra->log.mutex);

		mutex_destroy(&tegra->log.mutex);
	}
}

static void tegra_xusb_debugfs_init(struct tegra_xusb *tegra)
{
	struct device *dev = tegra->dev;
	char xhcivf[16];

	if (tegra->soc->is_xhci_vf) {
		snprintf(xhcivf, sizeof(xhcivf), "tegra_xhci_vf%d",
			tegra->soc->vf_id);
		tegra->debugfs_dir = debugfs_create_dir(xhcivf, NULL);
	} else {
		tegra->debugfs_dir = debugfs_create_dir("tegra_xhci", NULL);
	}

	if (IS_ERR_OR_NULL(tegra->debugfs_dir)) {
		tegra->debugfs_dir = NULL;
		dev_warn(dev, "debugfs_create_dir() for tegra_xhci failed\n");
		return;
	}

#ifdef CONFIG_USB_XHCI_HCD_DEBUGGING
	tegra->dump_ring_file = debugfs_create_file("dump_ring",
		(S_IWUSR|S_IWGRP), tegra->debugfs_dir, tegra, &dump_ring_fops);
	if (IS_ERR_OR_NULL(tegra->dump_ring_file)) {
		tegra->dump_ring_file = NULL;
		dev_warn(dev, "debugfs_create_file() for dump_ring failed\n");
		return;
        }
#endif

}

static void tegra_xusb_debugfs_deinit(struct tegra_xusb *tegra)
{
#ifdef CONFIG_USB_XHCI_HCD_DEBUGGING
	debugfs_remove(tegra->dump_ring_file);
	tegra->dump_ring_file = NULL;
#endif

	debugfs_remove(tegra->debugfs_dir);
	tegra->debugfs_dir = NULL;
}

static void tegra_xusb_disable_hsic_wake(struct tegra_xusb *tegra)
{
	u32 reg;

	reg = fpci_readl(tegra, XUSB_CFG_ARU_C11PAGESEL);
	reg |= XUSB_HSP0;
	fpci_writel(tegra, reg, XUSB_CFG_ARU_C11PAGESEL);

	reg = fpci_readl(tegra, XUSB_CFG_HSPX_CORE_CTRL);
	reg &= ~XUSB_HSIC_PLLCLK_VLD;
	fpci_writel(tegra, reg, XUSB_CFG_HSPX_CORE_CTRL);

	reg = fpci_readl(tegra, XUSB_CFG_ARU_C11PAGESEL);
	reg &= ~XUSB_HSP0;
	fpci_writel(tegra, reg, XUSB_CFG_ARU_C11PAGESEL);
}

static int tegra_xusb_set_ss_clk(struct tegra_xusb *tegra,
				 unsigned long rate)
{
	unsigned long new_parent_rate, old_parent_rate;
	struct clk *clk = tegra->ss_src_clk;
	unsigned int div;
	int err;

	if (clk_get_rate(clk) == rate)
		return 0;

	switch (rate) {
	case TEGRA_XHCI_SS_HIGH_SPEED:
		/*
		 * Reparent to PLLU_480M. Set divider first to avoid
		 * overclocking.
		 */
		if (!tegra->pll_u_480m) {
			dev_err(tegra->dev, "tegra->pll_u_480m is NULL\n");
			return -EINVAL;
		}

		old_parent_rate = clk_get_rate(clk_get_parent(clk));
		new_parent_rate = clk_get_rate(tegra->pll_u_480m);
		if (new_parent_rate == 0) {
			dev_err(tegra->dev, "new_parent_rate is zero\n");
			return -EINVAL;
		}
		div = new_parent_rate / rate;

		err = clk_set_rate(clk, old_parent_rate / div);
		if (err)
			return err;

		err = clk_set_parent(clk, tegra->pll_u_480m);
		if (err)
			return err;

		/*
		 * The rate should already be correct, but set it again just
		 * to be sure.
		 */
		err = clk_set_rate(clk, rate);
		if (err)
			return err;

		break;

	case TEGRA_XHCI_SS_LOW_SPEED:
		/* Reparent to CLK_M */
		err = clk_set_parent(clk, tegra->clk_m);
		if (err)
			return err;

		err = clk_set_rate(clk, rate);
		if (err)
			return err;

		break;

	default:
		dev_err(tegra->dev, "Invalid SS rate: %lu Hz\n", rate);
		return -EINVAL;
	}

	if (clk_get_rate(clk) != rate) {
		dev_err(tegra->dev, "SS clock doesn't match requested rate\n");
		return -EINVAL;
	}

	return 0;
}

static unsigned long extract_field(u32 value, unsigned int start,
				   unsigned int count)
{
	return (value >> start) & ((1 << count) - 1);
}

/* Command requests from the firmware */
enum tegra_xusb_mbox_cmd {
	MBOX_CMD_MSG_ENABLED = 1,
	MBOX_CMD_INC_FALC_CLOCK,
	MBOX_CMD_DEC_FALC_CLOCK,
	MBOX_CMD_INC_SSPI_CLOCK,
	MBOX_CMD_DEC_SSPI_CLOCK,
	MBOX_CMD_SET_BW, /* no ACK/NAK required */
	MBOX_CMD_SET_SS_PWR_GATING,
	MBOX_CMD_SET_SS_PWR_UNGATING,
	MBOX_CMD_SAVE_DFE_CTLE_CTX,
	MBOX_CMD_AIRPLANE_MODE_ENABLED,
	MBOX_CMD_AIRPLANE_MODE_DISABLED,
	MBOX_CMD_START_HSIC_IDLE,
	MBOX_CMD_STOP_HSIC_IDLE,
	MBOX_CMD_DBC_WAKE_STACK, /* unused */
	MBOX_CMD_HSIC_PRETEND_CONNECT,
	MBOX_CMD_RESET_SSPI,
	MBOX_CMD_DISABLE_SS_LFPS_DETECTION,
	MBOX_CMD_ENABLE_SS_LFPS_DETECTION,

	MBOX_CMD_MAX,

	/* Response message to above commands */
	MBOX_CMD_ACK = 128,
	MBOX_CMD_NAK
};

static const char * const mbox_cmd_name[] = {
	[  1] = "MSG_ENABLE",
	[  2] = "INC_FALCON_CLOCK",
	[  3] = "DEC_FALCON_CLOCK",
	[  4] = "INC_SSPI_CLOCK",
	[  5] = "DEC_SSPI_CLOCK",
	[  6] = "SET_BW",
	[  7] = "SET_SS_PWR_GATING",
	[  8] = "SET_SS_PWR_UNGATING",
	[  9] = "SAVE_DFE_CTLE_CTX",
	[ 10] = "AIRPLANE_MODE_ENABLED",
	[ 11] = "AIRPLANE_MODE_DISABLED",
	[ 12] = "START_HSIC_IDLE",
	[ 13] = "STOP_HSIC_IDLE",
	[ 14] = "DBC_WAKE_STACK",
	[ 15] = "HSIC_PRETEND_CONNECT",
	[ 16] = "RESET_SSPI",
	[ 17] = "DISABLE_SS_LFPS_DETECTION",
	[ 18] = "ENABLE_SS_LFPS_DETECTION",
	[128] = "ACK",
	[129] = "NAK",
};

struct tegra_xusb_mbox_msg {
	u32 cmd;
	u32 data;
};

static inline u32 tegra_xusb_mbox_pack(const struct tegra_xusb_mbox_msg *msg)
{
	return (msg->cmd & CMD_TYPE_MASK) << CMD_TYPE_SHIFT |
	       (msg->data & CMD_DATA_MASK) << CMD_DATA_SHIFT;
}
static inline void tegra_xusb_mbox_unpack(struct tegra_xusb_mbox_msg *msg,
					  u32 value)
{
	msg->cmd = (value >> CMD_TYPE_SHIFT) & CMD_TYPE_MASK;
	msg->data = (value >> CMD_DATA_SHIFT) & CMD_DATA_MASK;
}

static bool tegra_xusb_mbox_cmd_requires_ack(enum tegra_xusb_mbox_cmd cmd)
{
	switch (cmd) {
	case MBOX_CMD_SET_BW:
	case MBOX_CMD_ACK:
	case MBOX_CMD_NAK:
		return false;

	default:
		return true;
	}
}

static int tegra_xusb_mbox_send(struct tegra_xusb *tegra,
				const struct tegra_xusb_mbox_msg *msg)
{
	bool wait_for_idle = false;
	u32 value;

	/*
	 * Acquire the mailbox. The firmware still owns the mailbox for
	 * ACK/NAK messages.
	 */
	if (!(msg->cmd == MBOX_CMD_ACK || msg->cmd == MBOX_CMD_NAK)) {
		value = fpci_readl(tegra, tegra->soc->cfg_aru_mbox_owner);
		if (value != MBOX_OWNER_NONE) {
			dev_err(tegra->dev, "mailbox is busy\n");
			return -EBUSY;
		}

		fpci_writel(tegra, MBOX_OWNER_SW,
				tegra->soc->cfg_aru_mbox_owner);

		value = fpci_readl(tegra, tegra->soc->cfg_aru_mbox_owner);
		if (value != MBOX_OWNER_SW) {
			dev_err(tegra->dev, "failed to acquire mailbox\n");
			return -EBUSY;
		}

		wait_for_idle = true;
	}

	value = tegra_xusb_mbox_pack(msg);
	fpci_writel(tegra, value, tegra->soc->cfg_aru_mbox_data_in);

	value = fpci_readl(tegra, tegra->soc->cfg_aru_mbox_cmd);
	value |= MBOX_INT_EN | MBOX_DEST_FALC;
	fpci_writel(tegra, value, tegra->soc->cfg_aru_mbox_cmd);

	if (wait_for_idle) {
		unsigned long timeout = jiffies + msecs_to_jiffies(250);

		while (time_before(jiffies, timeout)) {
			value = fpci_readl(tegra,
					tegra->soc->cfg_aru_mbox_owner);
			if (value == MBOX_OWNER_NONE)
				break;

			/*
			 * fpga WAR: SW is too slow to see OWNER=NONE before
			 * FW issues next mbox command.
			 */
			if (tegra_platform_is_fpga() &&
				value != MBOX_OWNER_SW)
				break;

			usleep_range(10, 20);
		}

		if (!tegra_platform_is_fpga()) {

			if (time_after(jiffies, timeout))
				value = fpci_readl(tegra,
					tegra->soc->cfg_aru_mbox_owner);

			if (value != MBOX_OWNER_NONE)
				return -ETIMEDOUT;
		}
	}

	return 0;
}

static irqreturn_t tegra_xusb_mbox_irq(int irq, void *data)
{
	struct tegra_xusb *tegra = data;
	struct usb_hcd  *hcd = tegra->hcd;
	u32 value, value2;

	/* clear mailbox interrupts */
	value = fpci_readl(tegra, XUSB_CFG_ARU_SMI_INTR);
	fpci_writel(tegra, value, XUSB_CFG_ARU_SMI_INTR);

	/* read again to avoid spurious ARU SMI interrupt */
	value2 = fpci_readl(tegra, XUSB_CFG_ARU_SMI_INTR);

	if (value & MBOX_SMI_INTR_FW_HANG) {
		dev_err(tegra->dev, "controller firmware hang\n");
		tegra_xhci_hcd_reinit(hcd);
		return IRQ_HANDLED;
	}

	if (value & MBOX_SMI_INTR_EN)
		return IRQ_WAKE_THREAD;

	dev_warn(tegra->dev, "unhandled mbox irq: %08x %08x\n", value, value2);

	return value ? IRQ_HANDLED : IRQ_NONE;
}

static void tegra_xusb_mbox_handle(struct tegra_xusb *tegra,
				   const struct tegra_xusb_mbox_msg *msg)
{
	struct tegra_xusb_padctl *padctl = tegra->padctl;
	const struct tegra_xusb_soc *soc = tegra->soc;
	struct device *dev = tegra->dev;
	struct tegra_xusb_mbox_msg rsp;
	unsigned long mask;
	unsigned int port;
	bool idle, enable;
	int err = 0;
	memset(&rsp, 0, sizeof(rsp));

	switch (msg->cmd) {
	case MBOX_CMD_INC_FALC_CLOCK:
	case MBOX_CMD_DEC_FALC_CLOCK:
		rsp.data = clk_get_rate(tegra->falcon_clk) / 1000;
		if (rsp.data != msg->data)
			rsp.cmd = MBOX_CMD_NAK;
		else
			rsp.cmd = MBOX_CMD_ACK;

		break;

	case MBOX_CMD_INC_SSPI_CLOCK:
	case MBOX_CMD_DEC_SSPI_CLOCK:
		if (tegra->soc->scale_ss_clock) {
			err = tegra_xusb_set_ss_clk(tegra, msg->data * 1000);
			if (err < 0)
				rsp.cmd = MBOX_CMD_NAK;
			else
				rsp.cmd = MBOX_CMD_ACK;

			rsp.data = clk_get_rate(tegra->ss_src_clk) / 1000;
		} else {
			rsp.cmd = MBOX_CMD_ACK;
			rsp.data = msg->data;
		}

		break;

	case MBOX_CMD_SET_BW:
		/*
		 * TODO: Request bandwidth once EMC scaling is supported.
		 * Ignore for now since ACK/NAK is not required for SET_BW
		 * messages.
		 */
		break;

	case MBOX_CMD_SAVE_DFE_CTLE_CTX:
		err = tegra_xusb_padctl_usb3_save_context(padctl, msg->data);
		if (err < 0) {
			dev_err(dev, "failed to save context for USB3#%u: %d\n",
				msg->data, err);
			rsp.cmd = MBOX_CMD_NAK;
		} else {
			rsp.cmd = MBOX_CMD_ACK;
		}

		rsp.data = msg->data;
		break;

	case MBOX_CMD_START_HSIC_IDLE:
	case MBOX_CMD_STOP_HSIC_IDLE:
		if (msg->cmd == MBOX_CMD_STOP_HSIC_IDLE)
			idle = false;
		else
			idle = true;

		mask = extract_field(msg->data, 1 + soc->ports.hsic.offset,
				     soc->ports.hsic.count);

		for_each_set_bit(port, &mask, 32) {
			err = tegra_xusb_padctl_hsic_set_idle(padctl, port,
							      idle);
			if (err < 0)
				break;
		}

		if (err < 0) {
			dev_err(dev, "failed to set HSIC#%u %s: %d\n", port,
				idle ? "idle" : "busy", err);
			rsp.cmd = MBOX_CMD_NAK;
		} else {
			rsp.cmd = MBOX_CMD_ACK;
		}

		rsp.data = msg->data;
		break;

	case MBOX_CMD_DISABLE_SS_LFPS_DETECTION:
	case MBOX_CMD_ENABLE_SS_LFPS_DETECTION:
		if (msg->cmd == MBOX_CMD_DISABLE_SS_LFPS_DETECTION)
			enable = false;
		else
			enable = true;

		mask = extract_field(msg->data, 1 + soc->ports.usb3.offset,
				     soc->ports.usb3.count);

		for_each_set_bit(port, &mask, soc->ports.usb3.count) {
			err = tegra_xusb_padctl_usb3_set_lfps_detect(padctl,
								     port,
								     enable);
			if (err < 0)
				break;

			if (XHCI_IS_T210(tegra) && !enable) {
				/*
				 * Add this delay to increase stability of
				 * directing U3.
				 */
				usleep_range(500, 1000);
			}
		}

		if (err < 0) {
			dev_err(dev,
				"failed to %s LFPS detection on USB3#%u: %d\n",
				enable ? "enable" : "disable", port, err);
			rsp.cmd = MBOX_CMD_NAK;
		} else {
			rsp.cmd = MBOX_CMD_ACK;
		}

		rsp.data = msg->data;
		break;
	case MBOX_CMD_ACK:
		break;
	default:
		dev_warn(dev, "unknown message: %#x\n", msg->cmd);
		break;
	}

	if (rsp.cmd) {
		const char *cmd = (rsp.cmd == MBOX_CMD_ACK) ? "ACK" : "NAK";

		err = tegra_xusb_mbox_send(tegra, &rsp);
		if (err < 0)
			dev_err(dev, "failed to send %s: %d\n", cmd, err);
	}
}

static irqreturn_t tegra_xusb_mbox_thread(int irq, void *data)
{
	struct tegra_xusb *tegra = data;
	struct tegra_xusb_mbox_msg msg;
	u32 value;

	mutex_lock(&tegra->lock);

	if (tegra->suspended || pm_runtime_suspended(tegra->dev)) {
		mutex_unlock(&tegra->lock);
		return IRQ_HANDLED;
	}

	value = fpci_readl(tegra, tegra->soc->cfg_aru_mbox_data_out);
	tegra_xusb_mbox_unpack(&msg, value);

	value = fpci_readl(tegra, tegra->soc->cfg_aru_mbox_cmd);
	value &= ~MBOX_DEST_SMI;
	fpci_writel(tegra, value, tegra->soc->cfg_aru_mbox_cmd);

	/* clear mailbox owner if no ACK/NAK is required */
	if (!tegra_xusb_mbox_cmd_requires_ack(msg.cmd))
		fpci_writel(tegra, MBOX_OWNER_NONE,
				tegra->soc->cfg_aru_mbox_owner);

	tegra_xusb_mbox_handle(tegra, &msg);

	mutex_unlock(&tegra->lock);
	return IRQ_HANDLED;
}

static void tegra_xusb_config(struct tegra_xusb *tegra)
{
	struct resource *regs;
	u32 value;

	regs = platform_get_resource(to_platform_device(tegra->dev),
				     IORESOURCE_MEM, 0);

	if (tegra->soc->has_ipfs) {
		value = ipfs_readl(tegra, XUSB_HOST_CONFIGURATION_0);
		value |= IPFS_EN_FPCI;
		ipfs_writel(tegra, value, XUSB_HOST_CONFIGURATION_0);

		usleep_range(10, 20);
	}

	/* Program BAR0 space */
	value = fpci_readl(tegra, XUSB_CFG_4);
	value &= ~(tegra->soc->cfg_4_addr_mask << tegra->soc->cfg_4_addr_shift);
	value |= regs->start &
		(tegra->soc->cfg_4_addr_mask << tegra->soc->cfg_4_addr_shift);
	fpci_writel(tegra, value, XUSB_CFG_4);

	usleep_range(100, 200);

	/* Enable bus master */
	value = fpci_readl(tegra, XUSB_CFG_1);
	value |= XUSB_IO_SPACE_EN | XUSB_MEM_SPACE_EN | XUSB_BUS_MASTER_EN;
	fpci_writel(tegra, value, XUSB_CFG_1);

	if (tegra->soc->has_ipfs) {
		/* Enable interrupt assertion */
		value = ipfs_readl(tegra, XUSB_HOST_INTR_MASK_0);
		value |= IPFS_IP_INT_MASK;
		ipfs_writel(tegra, value, XUSB_HOST_INTR_MASK_0);

		/* Set hysteresis */
		ipfs_writel(tegra, 0x80, XUSB_HOST_CLKGATE_HYSTERESIS_0);
	}
}

static irqreturn_t tegra_xusb_padctl_irq(int irq, void *data)
{
	struct tegra_xusb *tegra = data;
	int i;
	bool oc = false;

	if (tegra->suspended)
		return IRQ_HANDLED;

	if (tegra->soc->handle_oc) {
		for (i = 0; i < tegra->soc->num_typed_phys[USB2_PHY]; i++) {
			if (tegra_xusb_padctl_overcurrent_detected(
				tegra->padctl,
				tegra->typed_phys[USB2_PHY][i]) > 0) {
				dev_warn(tegra->dev,
					"port %d over-current detected\n", i);
				oc = true;
				break;
			}
		}

		/* call padctl API to clear OC condition */
		if (oc)
			schedule_work(&tegra->oc_work);
	}

	pm_runtime_resume(tegra->dev);

	return IRQ_HANDLED;
}

static void tegra_xusb_parse_dt(struct platform_device *pdev,
				struct tegra_xusb *tegra)
{
	struct device_node *node = pdev->dev.of_node;

	tegra->cdp_internal = of_property_read_bool(node,
		"nvidia,enable-internal-cdp");
	if (tegra->cdp_internal) {
		dev_info(tegra->dev, "Enable CDP with internal USB2 phy\n");
		tegra->cdp_enabled = true;
	}
	of_property_read_u32(node, "nvidia,boost_cpu_freq",
					&tegra->boost_cpu_freq);
	of_property_read_u32(node, "nvidia,boost_cpu_trigger",
					&tegra->boost_cpu_trigger);
	tegra->hsic_set_idle = of_property_read_bool(node,
				   "nvidia,hsic-set-idle");
}

static int tegra_xusb_clk_enable(struct tegra_xusb *tegra)
{
	int err;

	if (tegra->clk_enabled)
		return 0;

	err = clk_prepare_enable(tegra->pll_e);
	if (err < 0)
		return err;

	err = clk_prepare_enable(tegra->host_clk);
	if (err < 0)
		goto disable_plle;

	err = clk_prepare_enable(tegra->ss_clk);
	if (err < 0)
		goto disable_host;

	err = clk_prepare_enable(tegra->falcon_clk);
	if (err < 0)
		goto disable_ss;

	err = clk_prepare_enable(tegra->fs_src_clk);
	if (err < 0)
		goto disable_falc;

	err = clk_prepare_enable(tegra->hs_src_clk);
	if (err < 0)
		goto disable_fs_src;

	if (XHCI_IS_T194(tegra)) {

		err = clk_prepare_enable(tegra->core_superspeed_clk);
		if (err < 0)
			goto disable_hs_src;

		err = clk_prepare_enable(tegra->falcon_host_clk);
		if (err < 0)
			goto disable_core_superspeed;

		err = clk_prepare_enable(tegra->falcon_superspeed_clk);
		if (err < 0)
			goto disable_falcon_host;

		err = clk_prepare_enable(tegra->fs_host_clk);
		if (err < 0)
			goto disable_falcon_superspeed;
	}

	if (tegra->soc->scale_ss_clock) {
		err = tegra_xusb_set_ss_clk(tegra, TEGRA_XHCI_SS_HIGH_SPEED);
		if (err < 0)
			goto disable_fs_host;
	}
	tegra->clk_enabled = true;

	return 0;

disable_fs_host:
	clk_disable_unprepare(tegra->fs_host_clk);
disable_falcon_superspeed:
	clk_disable_unprepare(tegra->falcon_superspeed_clk);
disable_falcon_host:
	clk_disable_unprepare(tegra->falcon_host_clk);
disable_core_superspeed:
	clk_disable_unprepare(tegra->core_superspeed_clk);
disable_hs_src:
	clk_disable_unprepare(tegra->hs_src_clk);
disable_fs_src:
	clk_disable_unprepare(tegra->fs_src_clk);
disable_falc:
	clk_disable_unprepare(tegra->falcon_clk);
disable_ss:
	clk_disable_unprepare(tegra->ss_clk);
disable_host:
	clk_disable_unprepare(tegra->host_clk);
disable_plle:
	clk_disable_unprepare(tegra->pll_e);
	return err;
}

static void tegra_xusb_clk_disable(struct tegra_xusb *tegra)
{
	if (tegra->clk_enabled) {
		if (XHCI_IS_T194(tegra)) {
			clk_disable_unprepare(tegra->core_superspeed_clk);
			clk_disable_unprepare(tegra->falcon_host_clk);
			clk_disable_unprepare(tegra->falcon_superspeed_clk);
			clk_disable_unprepare(tegra->fs_host_clk);
		}
		clk_disable_unprepare(tegra->pll_e);
		clk_disable_unprepare(tegra->host_clk);
		clk_disable_unprepare(tegra->ss_clk);
		clk_disable_unprepare(tegra->falcon_clk);
		clk_disable_unprepare(tegra->fs_src_clk);
		clk_disable_unprepare(tegra->hs_src_clk);
		tegra->clk_enabled = false;
	}
}

static int tegra_xusb_phy_enable(struct tegra_xusb *tegra)
{
	int i, j, err;

	/* enable CDP on non-OTG port */
	for (j = 0; j < tegra->soc->num_typed_phys[USB2_PHY]; j++) {
		if (is_otg_phy(tegra, USB2_PHY, j))
			continue;
		err = phy_init(tegra->cdp_ext_phys[j]);
		if (err)
			continue;
		err = phy_power_on(tegra->cdp_ext_phys[j]);
		if (err) {
			dev_err(tegra->dev, "phy_power_on failed");
			err = phy_exit(tegra->cdp_ext_phys[j]);
			if (err)
				dev_err(tegra->dev, "phy_exit failed");
		}
	}

	for (i = 0; i < MAX_PHY_TYPES; i++) {
		for (j = 0; j < tegra->soc->num_typed_phys[i]; j++) {
			err = phy_init(tegra->typed_phys[i][j]);
			if (err)
				goto disable_phy;

			err = phy_power_on(tegra->typed_phys[i][j]);
			if (err) {
				phy_exit(tegra->typed_phys[i][j]);
				goto disable_phy;
			}
		}
	}

	return 0;

disable_phy:
	for (; i >= 0; i--) {
		for (j = j - 1; j >= 0; j--) {
			phy_power_off(tegra->typed_phys[i][j]);
			phy_exit(tegra->typed_phys[i][j]);
		}
		if (i)
			j = tegra->soc->num_typed_phys[i - 1];
	}

	return err;
}

static void tegra_xusb_phy_disable(struct tegra_xusb *tegra)
{
	unsigned int i, j;

	for (i = 0; i < MAX_PHY_TYPES; i++) {
		for (j = 0; j < tegra->soc->num_typed_phys[i]; j++) {
			phy_power_off(tegra->typed_phys[i][j]);
			phy_exit(tegra->typed_phys[i][j]);
		}
	}

	/* disable CDP on non-OTG ports */
	for (i = 0; i < tegra->soc->num_typed_phys[USB2_PHY]; i++) {
		if (is_otg_phy(tegra, USB2_PHY, i))
			continue;
		phy_power_off(tegra->cdp_ext_phys[i]);
		phy_exit(tegra->cdp_ext_phys[i]);
	}
}

static int tegra_xhci_unpowergate_partitions(struct tegra_xusb *tegra)
{
	int ret;

	ret = tegra_unpowergate_partition(tegra->pgid_ss);
	if (ret) {
		dev_err(tegra->dev, "can't unpowergate SS partition\n");
		return ret;
	}

	ret = tegra_unpowergate_partition(tegra->pgid_host);
	if (ret) {
		dev_err(tegra->dev,
			"can't unpowergate Host partition\n");
		tegra_powergate_partition(tegra->pgid_ss);
	}

	return ret;
}

static int tegra_xhci_powergate_partitions(struct tegra_xusb *tegra)
{
	int ret;
	int err;

	ret = tegra_powergate_partition(tegra->pgid_host);
	if (ret) {
		dev_err(tegra->dev, "can't powergate Host partition\n");
		goto out;
	}

	ret = tegra_powergate_partition(tegra->pgid_ss);
	if (ret) {
		dev_err(tegra->dev, "can't powergate SS partition\n");
		err = tegra_unpowergate_partition(tegra->pgid_host);
		if (err) {
			dev_err(tegra->dev,
				"can't unpowergate host partition\n");
			goto out;
		}
	}

out:
	return ret;
}

static int tegra_xhci_load_firmware(struct tegra_xusb *tegra)
{
	unsigned int code_tag_blocks, code_size_blocks, code_blocks;
	struct xhci_cap_regs __iomem *cap_regs;
	struct xhci_op_regs __iomem *op_regs;
	struct tegra_xusb_fw_header *header;
	struct device *dev = tegra->dev;
	unsigned long timeout;
	time_t timestamp;
	struct tm time;
	u64 address;
	u32 value;

	header = (struct tegra_xusb_fw_header *)tegra->fw.virt;
	header->num_hsic_port = tegra->num_hsic_port;

	if (csb_readl(tegra, XUSB_CSB_MP_ILOAD_BASE_LO) != 0) {
		dev_info(dev, "Firmware already loaded, Falcon state %#x\n",
			 csb_readl(tegra, XUSB_FALC_CPUCTL));
		return 0;
	}

	if (header->build_log == LOG_MEMORY)
		fw_log_init(tegra);

	/* update the phys_log_buffer and total_entries here */
	if (test_bit(FW_LOG_CONTEXT_VALID, &tegra->log.flags)) {
		header->phys_addr_log_buffer = tegra->log.phys_addr;
		header->total_log_entries = FW_LOG_COUNT;
	}

	/* Program the size of DFI into ILOAD_ATTR. */
	csb_writel(tegra, tegra->fw.size, XUSB_CSB_MP_ILOAD_ATTR);

	/*
	 * Boot code of the firmware reads the ILOAD_BASE registers
	 * to get to the start of the DFI in system memory.
	 */
	address = tegra->fw.phys + sizeof(*header);
	csb_writel(tegra, address >> 32, XUSB_CSB_MP_ILOAD_BASE_HI);
	csb_writel(tegra, address, XUSB_CSB_MP_ILOAD_BASE_LO);

	/* Set BOOTPATH to 1 in APMAP. */
	csb_writel(tegra, APMAP_BOOTPATH, XUSB_CSB_MP_APMAP);

	/* Invalidate L2IMEM. */
	csb_writel(tegra, L2IMEMOP_INVALIDATE_ALL, XUSB_CSB_MP_L2IMEMOP_TRIG);

	/*
	 * Initiate fetch of bootcode from system memory into L2IMEM.
	 * Program bootcode location and size in system memory.
	 */
	code_tag_blocks = DIV_ROUND_UP(le32_to_cpu(header->boot_codetag),
				       IMEM_BLOCK_SIZE);
	code_size_blocks = DIV_ROUND_UP(le32_to_cpu(header->boot_codesize),
					IMEM_BLOCK_SIZE);
	code_blocks = code_tag_blocks + code_size_blocks;

	value = ((code_tag_blocks & L2IMEMOP_SIZE_SRC_OFFSET_MASK) <<
			L2IMEMOP_SIZE_SRC_OFFSET_SHIFT) |
		((code_size_blocks & L2IMEMOP_SIZE_SRC_COUNT_MASK) <<
			L2IMEMOP_SIZE_SRC_COUNT_SHIFT);
	csb_writel(tegra, value, XUSB_CSB_MP_L2IMEMOP_SIZE);

	/* Trigger L2IMEM load operation. */
	csb_writel(tegra, L2IMEMOP_LOAD_LOCKED_RESULT,
		   XUSB_CSB_MP_L2IMEMOP_TRIG);

	/* Setup Falcon auto-fill. */
	csb_writel(tegra, code_size_blocks, XUSB_FALC_IMFILLCTL);

	value = ((code_tag_blocks & IMFILLRNG1_TAG_MASK) <<
			IMFILLRNG1_TAG_LO_SHIFT) |
		((code_blocks & IMFILLRNG1_TAG_MASK) <<
			IMFILLRNG1_TAG_HI_SHIFT);
	csb_writel(tegra, value, XUSB_FALC_IMFILLRNG1);

	csb_writel(tegra, 0, XUSB_FALC_DMACTL);
	/* wait for RESULT_VLD to get set */
	timeout = jiffies + msecs_to_jiffies(10);
	do {
		value = csb_readl(tegra, XUSB_CSB_MEMPOOL_L2IMEMOP_RESULT);
		if (value & L2IMEMOP_RESULT_VLD)
			break;
		usleep_range(50, 60);
	} while (time_is_after_jiffies(timeout));

	value = csb_readl(tegra, XUSB_CSB_MEMPOOL_L2IMEMOP_RESULT);
	if (!(value & L2IMEMOP_RESULT_VLD)) {
		dev_err(dev, "DMA controller not ready 0x08%x\n", value);
		return -EFAULT;
	}

	csb_writel(tegra, le32_to_cpu(header->boot_codetag),
		   XUSB_FALC_BOOTVEC);

	/* Boot Falcon CPU and wait for USBSTS_CNR to get cleared. */
	csb_writel(tegra, CPUCTL_STARTCPU, XUSB_FALC_CPUCTL);

	cap_regs = tegra->regs;
	op_regs = tegra->regs + HC_LENGTH(ioread32(&cap_regs->hc_capbase));
	timeout = jiffies + msecs_to_jiffies(200);
	do {
		value = ioread32(&op_regs->status);
		if (!(value & STS_CNR))
			break;
		usleep_range(1000, 2000);
	} while (time_is_after_jiffies(timeout));

	value = ioread32(&op_regs->status);
	if (value & STS_CNR) {
		dev_err(dev, "XHCI Controller not ready. Falcon state: 0x%x\n",
			csb_readl(tegra, XUSB_FALC_CPUCTL));
		return -EIO;
	}

	timestamp = le32_to_cpu(header->fwimg_created_time);
	time_to_tm(timestamp, 0, &time);

	dev_info(dev, "Firmware timestamp: %ld-%02d-%02d %02d:%02d:%02d UTC, Version: %2x.%02x %s\n",
		 time.tm_year + 1900, time.tm_mon + 1, time.tm_mday,
		 time.tm_hour, time.tm_min, time.tm_sec,
		 FW_MAJOR_VERSION(header->version_id),
		 FW_MINOR_VERSION(header->version_id),
		 (header->build_log == LOG_MEMORY) ? "debug" : "release");

	return 0;
}

static void tegra_xusb_probe_finish(const struct firmware *fw, void *context);
static void tegra_firmware_retry_work(struct work_struct *work)
{
	struct tegra_xusb *tegra;
	struct device *dev;
	int ret;
	bool uevent = true;

	tegra = container_of(to_delayed_work(work),
			struct tegra_xusb, firmware_retry_work);
	dev = tegra->dev;

	if (++tegra->fw_retry_count >= FW_RETRY_COUNT) {
		/*
		 * Last retry.  If CONFIG_FW_LOADER_USER_HELPER_FALLBACK=y and
		 * uevent=true, in udev based systems, userspace will not get
		 * any chance to provide firmware file.  This happens due to
		 * udev stubs aborting firmware requests made by kernel.
		 *
		 * Hence try now with uevent=false so that udev does not abort
		 * syfs based firmware loading interface.  User can load the
		 * firmware later at any point.
		 *
		 * NOTE: If !CONFIG_FW_LOADER_USER_HELPER &&
		 * !CONFIG_FW_LOADER_USER_HELPER_FALLBACK, last retry will
		 * be a direct try from rootfs like the previous retries.
		 */
		uevent = false;
		dev_err(dev, "Leaving it upto user to load firmware!\n");
	}

	ret = request_firmware_nowait(THIS_MODULE, uevent,
				tegra->soc->firmware,
				tegra->dev, GFP_KERNEL, tegra,
				tegra_xusb_probe_finish);
	if (ret) {
		dev_err(dev,
			"Could not submit async request for firmware load %d\n"
			, ret);
		usb_put_hcd(tegra->hcd);
		tegra->hcd = NULL;
	}
}

static void downgrade_usb3(struct device *dev, unsigned int downgrade_enabled);

static void tegra_xhci_set_host_mode(struct tegra_xusb *tegra, int i, bool on)
{
	struct xhci_hcd *xhci;
	u32 status;
	int wait;
	struct tegra_xusb_mbox_msg msg;
	int ret;
	struct xusb_otg_port *port;

	port = &tegra->otg_ports[i];
	dev_dbg(tegra->dev, "%s: vbus_id #%d, usb2 #%d\n", __func__,
			i, port ? port->usb2_otg_port_base_1 - 1 : -1);

	if (!port)
		return;

	if (!tegra->fw_loaded && !tegra->soc->is_xhci_vf)
		return;

	xhci = hcd_to_xhci(tegra->hcd);

	if (xhci->recovery_in_progress == true)
		return;

	mutex_lock(&tegra->lock);

	if (tegra->suspended) {
		mutex_unlock(&tegra->lock);
		return;
	}

	if (!on)
		tegra_xusb_padctl_clear_id_override(tegra->padctl, i);

	if (!port->inited && on)
		goto role_update;

	if ((port->host_mode && on) || (!port->host_mode && !on)) {
		mutex_unlock(&tegra->lock);
		return;
	}

role_update:

	port->host_mode = on;
	port->inited = true;
	dev_dbg(tegra->dev, "host mode %s on #%d\n", on ? "on" : "off", i);

	if (!pm_runtime_suspended(tegra->dev)) {
		if (on)
			tegra_xusb_padctl_set_id_override(tegra->padctl, i);
	}

	mutex_unlock(&tegra->lock);

	if (!tegra->soc->otg_set_port_power) {
		pm_runtime_get_sync(tegra->dev);
		if (on)
			pm_runtime_mark_last_busy(tegra->dev);
		pm_runtime_put_autosuspend(tegra->dev);
		return;
	}

	pm_runtime_get_sync(tegra->dev);
	if (on) {
		/* switch to host mode */
		if (port->usb3_otg_port_base_1) {
			if (XHCI_IS_T210(tegra)) {
				/* set PP=0 */
				xhci_hub_control(xhci->shared_hcd, GetPortStatus
					, 0, port->usb3_otg_port_base_1
					, (char *) &status, sizeof(status));
				if (status & USB_SS_PORT_STAT_POWER) {
					xhci_hub_control(xhci->shared_hcd,
						ClearPortFeature,
						USB_PORT_FEAT_POWER,
						port->usb3_otg_port_base_1,
						NULL, 0);
				}

				wait = 10;
				do {
					xhci_hub_control(xhci->shared_hcd
						, GetPortStatus, 0
						, port->usb3_otg_port_base_1
						, (char *) &status
						, sizeof(status));
					if (!(status & USB_SS_PORT_STAT_POWER))
						break;
					usleep_range(10, 20);
				} while (--wait > 0);

				/* reset OTG port SSPI */
				msg.cmd = MBOX_CMD_RESET_SSPI;
				msg.data = port->usb3_otg_port_base_1;

				ret = tegra_xusb_mbox_send(tegra, &msg);
				if (ret < 0) {
					dev_err(tegra->dev,
						"failed to RESET_SSPI %d\n",
						ret);
				}
			}

			xhci_hub_control(xhci->shared_hcd, SetPortFeature,
				USB_PORT_FEAT_POWER, port->usb3_otg_port_base_1
				, NULL, 0);

			wait = 10;
			do {
				xhci_hub_control(xhci->shared_hcd, GetPortStatus
					, 0, port->usb3_otg_port_base_1
					, (char *) &status, sizeof(status));
				if (status & USB_SS_PORT_STAT_POWER)
					break;
				usleep_range(10, 20);
			} while (--wait > 0);

			if (!(status & USB_SS_PORT_STAT_POWER))
				dev_info(tegra->dev, "failed to set SS PP\n");

			downgrade_usb3(tegra->dev, tegra->downgrade_enabled);
		}

		xhci_hub_control(xhci->main_hcd, SetPortFeature,
			USB_PORT_FEAT_POWER, port->usb2_otg_port_base_1,
			NULL, 0);

		wait = 10;
		do {
			xhci_hub_control(xhci->main_hcd, GetPortStatus
				, 0, port->usb2_otg_port_base_1
				, (char *) &status, sizeof(status));
			if (status & USB_PORT_STAT_POWER)
				break;
			usleep_range(10, 20);
		} while (--wait > 0);

		if (!(status & USB_PORT_STAT_POWER))
			dev_info(tegra->dev, "failed to set HS PP\n");

		pm_runtime_mark_last_busy(tegra->dev);
	} else {
		if (port->usb3_otg_port_base_1) {
			xhci_hub_control(xhci->shared_hcd, ClearPortFeature,
				USB_PORT_FEAT_POWER, port->usb3_otg_port_base_1
				, NULL, 0);

			wait = 1000;
			do {
				xhci_hub_control(xhci->shared_hcd, GetPortStatus
					, 0, port->usb3_otg_port_base_1
					, (char *) &status, sizeof(status));
				if (!(status & USB_SS_PORT_STAT_POWER))
					break;
				usleep_range(600, 700);
			} while (--wait > 0);

			if (status & USB_SS_PORT_STAT_POWER)
				dev_info(tegra->dev, "failed to clear SS PP\n");
		}

		xhci_hub_control(xhci->main_hcd, ClearPortFeature,
			USB_PORT_FEAT_POWER, port->usb2_otg_port_base_1,
			NULL, 0);

		wait = 10;
		do {
			xhci_hub_control(xhci->main_hcd, GetPortStatus
				, 0, port->usb2_otg_port_base_1
				, (char *) &status, sizeof(status));
			if (!(status & USB_PORT_STAT_POWER))
				break;
			usleep_range(10, 20);
		} while (--wait > 0);

		if (status & USB_PORT_STAT_POWER)
			dev_info(tegra->dev, "failed to clear HS PP\n");

	}
	pm_runtime_put_autosuspend(tegra->dev);
}

static void tegra_xhci_update_otg_role(struct tegra_xusb *tegra, bool check)
{
	int state;
	struct xusb_otg_port *port;
	int i;

	if (tegra_platform_is_fpga()) {
		tegra_xhci_set_host_mode(tegra, 0, true);
		return;
	}

	if (check) {
		for (i = 0; i < tegra->otg_port_num; i++) {
			port = &tegra->otg_ports[i];

			if (port->edev == NULL)
				return;
			if (extcon_get_cable_state_(port->edev,
						EXTCON_USB_HOST))
				port->changed = true;
		}
	}

	for (i = 0; i < tegra->otg_port_num; i++) {
		port = &tegra->otg_ports[i];

		if (port->edev == NULL)
			return;
		if (!port->changed)
			continue;
		state = extcon_get_cable_state_(port->edev, EXTCON_USB_HOST);
		tegra_xhci_set_host_mode(tegra, i, !!state);
		port->changed = false;
	}
}

static void tegra_xhci_id_extcon_work(struct work_struct *work)
{
	struct tegra_xusb *tegra = container_of(work, struct tegra_xusb,
						    id_extcons_work);

	tegra_xhci_update_otg_role(tegra, false);
}

static int tegra_xhci_id_notifier(struct notifier_block *nb,
					 unsigned long action, void *data)
{
	struct extcon_dev *edev = (struct extcon_dev *) data;
	struct tegra_xusb *tegra = container_of(nb, struct tegra_xusb,
						    id_extcons_nb);
	int i;
	struct xusb_otg_port *port;

	for (i = 0; i < tegra->otg_port_num; i++) {
		port = &tegra->otg_ports[i];
		if (port->edev == edev) {
			port->changed = true;
			schedule_work(&tegra->id_extcons_work);
			break;
		}
	}

	return NOTIFY_OK;
}


static irqreturn_t tegra_xhci_pad_ivc_irq(int irq, void *data)
{
	struct tegra_xusb *tegra = data;
	int ret;

	if (tegra_hv_ivc_channel_notified(tegra->ivck) != 0) {
		dev_info(tegra->dev, "ivc channel not usable\n");
		return IRQ_HANDLED;
	}

	if (tegra_hv_ivc_can_read(tegra->ivck)) {
		/* Read the current message for the xhci_server to be
		 * able to send further messages on next pad interrupt
		 */
		ret = tegra_hv_ivc_read(tegra->ivck, tegra->ivc_rx, 128);
		if (ret < 0) {
			dev_err(tegra->dev,
				"IVC Read of PAD Interrupt Failed: %d\n", ret);
		} else {
			/* Schedule work to execute the PADCTL IRQ Function
			 * which takes the appropriate action.
			 */
			schedule_work(&tegra->ivc_work);
		}
	} else {
		dev_info(tegra->dev, "Can not read ivc channel: %d\n",
							tegra->ivck->irq);
	}
	return IRQ_HANDLED;
}

static void tegra_xhci_ivc_work(struct work_struct *work)
{
	struct tegra_xusb *tegra = container_of(work, struct tegra_xusb,
						ivc_work);

	tegra_xusb_padctl_irq(tegra->ivck->irq, tegra);
}

static int init_ivc_communication(struct platform_device *pdev)
{
	uint32_t id;
	int ret;
	struct device *dev = &pdev->dev;
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);
	struct device_node *np, *hv_np;

	np = dev->of_node;
	if (!np) {
		dev_err(dev, "init_ivc: couldnt get of_node handle\n");
		return -EINVAL;
	}

	hv_np = of_parse_phandle(np, "ivc", 0);
	if (!hv_np) {
		dev_err(dev, "ivc_init: couldnt find ivc DT node\n");
		return -EINVAL;
	}

	ret = of_property_read_u32_index(np, "ivc", 1, &id);
	if (ret) {
		dev_err(dev, "ivc_init: Error in reading IVC DT\n");
		of_node_put(hv_np);
		return -EINVAL;
	}

	tegra->ivck = tegra_hv_ivc_reserve(hv_np, id, NULL);
	of_node_put(hv_np);
	if (IS_ERR_OR_NULL(tegra->ivck)) {
		dev_err(dev, "Failed to reserve ivc channel:%d\n", id);
		ret = PTR_ERR(tegra->ivck);
		tegra->ivck = NULL;
		return ret;
	}

	dev_info(dev, "Reserved IVC channel #%d - frame_size=%d irq %d\n",
			id, tegra->ivck->frame_size, tegra->ivck->irq);

	tegra_hv_ivc_channel_reset(tegra->ivck);

	INIT_WORK(&tegra->ivc_work, tegra_xhci_ivc_work);

	ret = devm_request_irq(dev, tegra->ivck->irq, tegra_xhci_pad_ivc_irq,
						0, dev_name(dev), tegra);
	if (ret) {
		dev_err(dev, "Unable to request irq(%d)\n", tegra->ivck->irq);
		tegra_hv_ivc_unreserve(tegra->ivck);
		return ret;
	}

	return 0;
}

static ssize_t store_reload_hcd(struct device *dev,
	struct device_attribute *attr,
	const char *buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);
	struct usb_hcd	*hcd = tegra->hcd;
	int ret, reload;

	ret = kstrtoint(buf, 0, &reload);
	if (ret != 0 || reload < 0 || reload > 1)
		return -EINVAL;

	if (reload)
		tegra_xhci_hcd_reinit(hcd);

	return count;
}
static DEVICE_ATTR(reload_hcd, 0200, NULL, store_reload_hcd);

static int tegra_xusb_power(struct tegra_xusb *tegra, bool on)
{
	struct tegra_xusb_mbox_msg msg;
	int rc;

	if (on == tegra->hsic_power_on)
		return 0;

	if (on)
		msg.cmd = MBOX_CMD_AIRPLANE_MODE_DISABLED;
	else
		msg.cmd = MBOX_CMD_AIRPLANE_MODE_ENABLED;

	msg.data = BIT(tegra->soc->ports.hsic.offset + 1);

	rc = tegra_xusb_mbox_send(tegra, &msg);
	if (rc < 0) {
		dev_err(tegra->dev,
			"failed to send message to firmware %d\n", rc);
		return rc;
	}

	if (on)
		rc = tegra_xusb_padctl_hsic_set_idle(tegra->padctl, 0, true);
	else
		rc = tegra_xusb_padctl_hsic_reset(tegra->padctl, 0);

	if (rc != 0) {
		dev_err(tegra->dev, "failed to set padctl %d\n", rc);
		return rc;
	}

	tegra->hsic_power_on = on;
	return 0;
}

static void tegra_xhci_downgrade_check_to_disable(struct usb_hcd *hcd,
	struct usb_device *udev, bool restore_usb3_power)
{
	struct list_head *ptr;
	struct usb_downgraded_port *port_ptr;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);
	u32 portsc;
	char serial[31];
	unsigned long flags;

	if (udev->serial) {
		strncpy(serial, udev->serial, 30);
		serial[30] = 0;
	} else {
		serial[0] = 0;
	}

	mutex_lock(&tegra->lock);
	if (!list_empty(&hub_downgraded_list)) {
		list_for_each(ptr, &hub_downgraded_list) {
			port_ptr = list_entry(ptr,
				struct usb_downgraded_port, downgraded_list);
			if ((udev->descriptor.idVendor ==
				port_ptr->id_vendor) &&
			    (udev->descriptor.idProduct ==
				port_ptr->id_product)) {
				if (!port_ptr->serial[0] && !serial[0])
					break;
				if (port_ptr->serial[0] && serial[0] &&
				    !strcmp(port_ptr->serial, serial))
					break;
			}
		}

		if (ptr != &hub_downgraded_list) {
			list_del(&port_ptr->downgraded_list);
			/* Clear id_vendor as empty entry */
			port_ptr->id_vendor = 0;

			if (!restore_usb3_power) {
				mutex_unlock(&tegra->lock);
				return;
			}
			dev_info(&udev->dev,
				"Upgrade idVendor=%04x idProduct=%04x to USB3.0\n",
				le16_to_cpu(udev->descriptor.idVendor),
				le16_to_cpu(udev->descriptor.idProduct));
			pm_runtime_get_noresume(hcd->self.controller);
			/* Port Power on for downgraded USB3.0 port */
			spin_lock_irqsave(&xhci->lock, flags);
			portsc = readl(xhci->usb3_ports[port_ptr->portnum
				- 1]);
			if (!(portsc & PORT_POWER)) {
				portsc |= PORT_POWER;
				writel(portsc,
					xhci->usb3_ports[port_ptr->portnum
					- 1]);
				spin_unlock_irqrestore(&xhci->lock, flags);
				usleep_range(10000, 12000);
				spin_lock_irqsave(&xhci->lock, flags);
				portsc = readl(
					xhci->usb3_ports[port_ptr->portnum
					- 1]);
				/* Exit from SS.disabled */
				portsc &= ~(PORT_PLS_MASK | PORT_PE);
				portsc |= (PORT_POWER | XDEV_RXDETECT |
					PORT_LINK_STROBE);
				writel(portsc,
					xhci->usb3_ports[port_ptr->portnum
					- 1]);
			}
			spin_unlock_irqrestore(&xhci->lock, flags);
			pm_runtime_put(hcd->self.controller);
		}
	}
	mutex_unlock(&tegra->lock);
}

static ssize_t downgrade_usb3_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);

	return sprintf(buf, "%d\n", tegra->downgrade_enabled);
}

static void tegra_xhci_downgrade_check_to_enable(struct usb_hcd *hcd,
				    struct usb_device *udev);
static int tegra_xhci_exit_elpg(struct tegra_xusb *tegra, bool runtime);

static void downgrade_usb3(struct device *dev, unsigned int downgrade_enabled)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);
	struct xhci_hcd *xhci = hcd_to_xhci(tegra->hcd);
	struct usb_device *hdev20 = xhci->main_hcd->self.root_hub;
	struct usb_hub *hub20 = usb_hub_to_struct_hub(hdev20);
	struct usb_device *hdev30 = xhci->shared_hcd->self.root_hub;
	struct usb_hub *hub30 = usb_hub_to_struct_hub(hdev30);
	struct usb_hcd *hcd;
	struct usb_device *udev;
	unsigned int port1;
	u32 portsc;
	int power_up_wait;
	unsigned long flags;

	hcd = tegra->hcd;
	if ((downgrade_enabled == 0xffffffff) || (downgrade_enabled == 0)) {
		for (port1 = 1; port1 <= hdev20->maxchild; port1++) {
			udev = hub20->ports[port1 - 1]->child;
			if (udev)
				tegra_xhci_downgrade_check_to_disable(hcd,
					udev, false);
		}

		pm_runtime_get_sync(hcd->self.controller);
		mutex_lock(&tegra->lock);
		spin_lock_irqsave(&xhci->lock, flags);
		power_up_wait = 0;
		for (port1 = 1; port1 <= hdev30->maxchild; port1++) {
			if (port1 > DEGRADED_PORT_COUNT)
				break;
			portsc = readl(xhci->usb3_ports[port1 - 1]);
			if (downgrade_enabled == 0xffffffff) {
				if (portsc & PORT_POWER) {
					/* To disconnect */
					portsc |= PORT_PE;
					writel(portsc, xhci->usb3_ports[port1
						- 1]);
					power_up_wait++;
				}
			} else {
				if (!(portsc & PORT_POWER)) {
					portsc |= PORT_POWER;
					writel(portsc, xhci->usb3_ports[port1
						- 1]);
					power_up_wait++;
				}
			}
		}
		if (power_up_wait) {
			spin_unlock_irqrestore(&xhci->lock, flags);
			usleep_range(10000, 12000);
			spin_lock_irqsave(&xhci->lock, flags);
		}
		if (downgrade_enabled == 0xffffffff) {
			for (port1 = 1; port1 <= hdev30->maxchild; port1++) {
				if (port1 > DEGRADED_PORT_COUNT)
					break;
				portsc = readl(xhci->usb3_ports[port1 - 1]);
				if (portsc & PORT_POWER) {
					dev_info(dev,
						"Downgrade port %d to USB2.0\n"
						, port1 - 1);
					/* Exit from SS.disabled */
					portsc &= ~(PORT_PLS_MASK | PORT_PE);
					portsc |= (PORT_POWER | XDEV_RXDETECT |
						PORT_LINK_STROBE);
					writel(portsc, xhci->usb3_ports[port1
						- 1]);
					spin_unlock_irqrestore(&xhci->lock,
						flags);
					usleep_range(1000, 2000);
					spin_lock_irqsave(&xhci->lock, flags);

					portsc = readl(xhci->usb3_ports[port1
						- 1]);
					portsc &= ~(PORT_POWER | PORT_PE |
						PORT_CSC);
					writel(portsc, xhci->usb3_ports[port1
						- 1]);
				}
			}
		}
		if (downgrade_enabled == 0) {
			for (port1 = 1; port1 <= hdev30->maxchild; port1++) {
				if (port1 > DEGRADED_PORT_COUNT)
					break;
				dev_info(dev, "Upgrade port %d to USB3.0\n",
					port1 - 1);
				portsc = readl(xhci->usb3_ports[port1 - 1]);
				if ((portsc & PORT_PLS_MASK) == XDEV_DISABLED) {
					/* Exit from SS.disabled */
					portsc &= ~(PORT_PLS_MASK | PORT_PE);
					portsc |= (PORT_POWER | XDEV_RXDETECT |
						PORT_LINK_STROBE);
					writel(portsc, xhci->usb3_ports[port1 -
						1]);
					spin_unlock_irqrestore(&xhci->lock,
						flags);
					usleep_range(1000, 2000);
					spin_lock_irqsave(&xhci->lock, flags);
				}
			}
			if (!power_up_wait) {
				spin_unlock_irqrestore(&xhci->lock, flags);
				mutex_unlock(&tegra->lock);
				pm_runtime_put(hcd->self.controller);
				return;
			}
			/* USB2.0 port reset to transition device to USB3.0 */
			for (port1 = 1; port1 <= hdev20->maxchild; port1++) {
				udev = hub20->ports[port1 - 1]->child;
				if (udev && udev->speed >= USB_SPEED_HIGH) {
					portsc = readl(xhci->usb2_ports[port1
						- 1]);
					portsc &= ~PORT_PE;
					portsc |= (PORT_POWER | PORT_RESET);
					writel(portsc, xhci->usb2_ports[port1
						- 1]);
				}
			}
		}
		spin_unlock_irqrestore(&xhci->lock, flags);
		mutex_unlock(&tegra->lock);
		pm_runtime_put(hcd->self.controller);

		return;
	}
	for (port1 = 1; port1 <= hdev30->maxchild; port1++) {
		if (port1 > DEGRADED_PORT_COUNT)
			break;
		udev = hub30->ports[port1 - 1]->child;
		if (udev && downgrade_enabled)
			tegra_xhci_downgrade_check_to_enable(hcd, udev);
	}
}

static ssize_t downgrade_usb3_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);
	unsigned int downgrade_enabled;
	unsigned int old_downgrade_enabled;

	if (kstrtouint(buf, 16, &downgrade_enabled))
		return -EINVAL;

	mutex_lock(&tegra->lock);
	old_downgrade_enabled = tegra->downgrade_enabled;
	tegra->downgrade_enabled = downgrade_enabled;
	mutex_unlock(&tegra->lock);

	if (!tegra->fw_loaded) {
		return n;
	}

	/* Restore power */
	if ((old_downgrade_enabled == 0xffffffff) &&
	    (downgrade_enabled == 1)) {
		downgrade_usb3(dev, 0);
		msleep(1000);
	}
	downgrade_usb3(dev, downgrade_enabled);

	return n;
}

static DEVICE_ATTR(
	downgrade_usb3, 0644, downgrade_usb3_show, downgrade_usb3_store);

static void tegra_xusb_host_vbus_power_on(struct tegra_xusb *tegra)
{
	u32 i;

	for (i = 0u; i < tegra->soc->num_typed_phys[USB2_PHY]; i++) {
		if (tegra->typed_phys[USB2_PHY][i] == NULL)
			continue;

		/* skip vbus on for OTG port */
		if (!is_otg_phy(tegra, USB2_PHY, (int)i)) {
			u32 port = i;

			if (tegra->soc->is_xhci_vf)
				port = (u32)tegra->port_to_phy[USB2_PHY][i];

			(void)tegra_xusb_padctl_vbus_power_on(
				tegra->padctl, port);
		}
	}
}

static void tegra_xusb_host_vbus_power_off(struct tegra_xusb *tegra)
{
	u32 i;

	for (i = 0u; i < tegra->soc->num_typed_phys[USB2_PHY]; i++) {
		if (tegra->typed_phys[USB2_PHY][i] == NULL)
			continue;

		/* skip vbus on for OTG port */
		if (!is_otg_phy(tegra, USB2_PHY, (int)i)) {
			u32 port = i;

			if (tegra->soc->is_xhci_vf)
				port = (u32)tegra->port_to_phy[USB2_PHY][i];

			(void)tegra_xusb_padctl_vbus_power_off(
				tegra->padctl, port);
		}
	}
}

static void tegra_xusb_probe_finish(const struct firmware *fw, void *context)
{
	struct tegra_xusb *tegra = context;
	struct device *dev = tegra->dev;
	struct platform_device *pdev = to_platform_device(dev);
	struct xhci_hcd *xhci = NULL;
	struct tegra_xusb_fw_header *header;
	struct tegra_xusb_mbox_msg msg;
	struct resource *regs;
	int ret;
	u32 val;

	if (!tegra->soc->is_xhci_vf) {
		if (!fw) {
			if (tegra->fw_retry_count >= FW_RETRY_COUNT) {
				dev_err(dev, "Giving up on firmware\n");
				goto put_usb2;
			}

			dev_info(dev, "cannot find firmware....retry after 1 second\n");
			schedule_delayed_work(&tegra->firmware_retry_work,
						msecs_to_jiffies(1000));
			return;
		}

		/* Load Falcon controller with its firmware. */
		header = (struct tegra_xusb_fw_header *)fw->data;
		tegra->fw.size = le32_to_cpu(header->fwimg_len);

		tegra->fw.virt = dma_alloc_coherent(tegra->dev, tegra->fw.size,
						&tegra->fw.phys, GFP_KERNEL);
		if (!tegra->fw.virt) {
			dev_err(tegra->dev, "failed to allocate memory for firmware\n");
			release_firmware(fw);
			return;
		}

		memcpy(tegra->fw.virt, fw->data, tegra->fw.size);
		release_firmware(fw);

		ret = tegra_xhci_load_firmware(tegra);
		if (ret < 0) {
			dev_err(dev, "can't load firmware (%d)\n", ret);
			return;
		}
	}

	tegra_xusb_host_vbus_power_on(tegra);

	tegra->hcd = usb_create_hcd(&tegra_xhci_hc_driver, dev, dev_name(dev));
	if (!tegra->hcd) {
		dev_err(dev, "failed to create shared HCD\n");
		return;
	}

	/*
	 * This must happen after usb_create_hcd(), because usb_create_hcd()
	 * will overwrite the drvdata of the device with the hcd it creates.
	 */
	platform_set_drvdata(pdev, tegra);

	regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	tegra->hcd->regs = tegra->regs;
	tegra->hcd->rsrc_start = regs->start;
	tegra->hcd->rsrc_len = resource_size(regs);

	ret = usb_add_hcd(tegra->hcd, tegra->xhci_irq, IRQF_SHARED);
	if (ret < 0) {
		dev_err(dev, "failed to add main HCD: %d\n", ret);
		goto put_usb2;
	}

	device_wakeup_enable(tegra->hcd->self.controller);

	xhci = hcd_to_xhci(tegra->hcd);

	xhci->shared_hcd = usb_create_shared_hcd(&tegra_xhci_hc_driver,
						 dev,
						 dev_name(dev),
						 tegra->hcd);
	if (!xhci->shared_hcd) {
		dev_err(dev, "failed to create shared HCD\n");
		goto remove_usb2;
	}

	if (HCC_MAX_PSA(xhci->hcc_params) >= 4)
		xhci->shared_hcd->can_do_streams = 1;

	ret = usb_add_hcd(xhci->shared_hcd, tegra->xhci_irq, IRQF_SHARED);
	if (ret < 0) {
		dev_err(dev, "failed to add shared HCD: %d\n", ret);
		goto put_usb3;
	}

	/* Enable wake for both USB2.0 and USB3.0 hub */
	device_init_wakeup(&tegra->hcd->self.root_hub->dev, true);
	device_init_wakeup(&xhci->shared_hcd->self.root_hub->dev, true);

	/* Enable firmware messages from controller. */
	if (!tegra->soc->is_xhci_vf) {
		mutex_lock(&tegra->lock);

		msg.cmd = MBOX_CMD_MSG_ENABLED;
		msg.data = 0;

		ret = tegra_xusb_mbox_send(tegra, &msg);
		if (ret < 0) {
			dev_err(dev, "failed to enable messages: %d\n", ret);
			mutex_unlock(&tegra->lock);
			goto remove_usb3;
		}
		mutex_unlock(&tegra->lock);

		ret = devm_request_threaded_irq(dev, tegra->mbox_irq,
						tegra_xusb_mbox_irq,
						tegra_xusb_mbox_thread,
						IRQF_ONESHOT,
						dev_name(dev), tegra);
		if (ret < 0) {
			dev_err(dev,
			"failed to request mailbox IRQ: %d\n", ret);
			goto remove_usb3;
		}

		ret = devm_request_threaded_irq(dev, tegra->padctl_irq,
						NULL,
						tegra_xusb_padctl_irq,
						IRQF_ONESHOT |
						IRQF_TRIGGER_HIGH,
						dev_name(dev), tegra);
		if (ret < 0) {
			dev_err(dev, "failed to request padctl IRQ: %d\n", ret);
			goto remove_mbox_irq;
		}
		downgrade_usb3(dev, tegra->downgrade_enabled);
		tegra->fw_loaded = true;
	} else {
		/* In Virtualization, the PAD interrupt is owned by xhci_server
		 *  and Host driver needs to initiate an IVC channel to receive
		 * the interruptd from the xhci_server.
		 */
		ret = init_ivc_communication(pdev);
		if (ret < 0) {
			dev_err(dev,
			"Failed to init IVC channel with xhci_server\n");
			goto remove_usb3;
		}
	}

	tegra_xhci_update_otg_role(tegra, true);

	if (tegra->hsic_set_idle) {
		ret = tegra_xusb_power(tegra, true);
		if (ret)
			dev_dbg(dev, "failed to power-on on startup");
	}

	pm_runtime_use_autosuspend(dev);
	pm_runtime_set_autosuspend_delay(dev, 2000);
	pm_runtime_mark_last_busy(tegra->dev);
	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	ret = device_create_file(dev, &dev_attr_reload_hcd);
	if (ret) {
		dev_err(dev,
			"Can't register reload_hcd attribute\n");
		goto remove_padctl_irq;
	}

	tegra->fwdev = devm_tegrafw_register(dev, NULL,
			TFW_NORMAL, fw_version_show, NULL);
	if (IS_ERR(tegra->fwdev))
		dev_warn(dev, "cannot register firmware reader");

	/* Enable EU3S bit of USBCMD */
	val = readl(&xhci->op_regs->command);
	val |= CMD_PM_INDEX;
	writel(val, &xhci->op_regs->command);

	INIT_WORK(&xhci->tegra_xhci_reinit_work, xhci_reinit_work);
	xhci->recovery_in_progress = false;
	xhci->pdev = to_platform_device(dev);

	return;

	/* Free up as much as we can and wait to be unbound. */
remove_padctl_irq:
	if (!tegra->soc->is_xhci_vf) {
		devm_free_irq(dev, tegra->padctl_irq, tegra);
	} else {
		devm_free_irq(dev, tegra->ivck->irq, tegra);
		tegra_hv_ivc_unreserve(tegra->ivck);
	}
remove_mbox_irq:
	if (!tegra->soc->is_xhci_vf)
		devm_free_irq(dev, tegra->mbox_irq, tegra);
remove_usb3:
	usb_remove_hcd(xhci->shared_hcd);
put_usb3:
	usb_put_hcd(xhci->shared_hcd);
remove_usb2:
	usb_remove_hcd(tegra->hcd);
put_usb2:
	usb_put_hcd(tegra->hcd);
	tegra->hcd = NULL;
	sysfs_remove_file(&pdev->dev.kobj, &dev_attr_downgrade_usb3.attr);
}

static void tegra_xhci_init_otg_cap(struct tegra_xusb *tegra, int vbus_id,
		int usb2_port, int usb3_port)
{
	struct xusb_otg_port *port = &tegra->otg_ports[vbus_id];

	port->usb2_otg_port_base_1 = usb2_port + 1;
	port->usb3_otg_port_base_1 = usb3_port + 1;
	port->edev = NULL;
	port->changed = false;
	port->host_mode = false;

	dev_dbg(tegra->dev, "vbus_id %d: bind usb2 %d and usb3 %d\n",
		vbus_id, port->usb2_otg_port_base_1 - 1,
		port->usb3_otg_port_base_1 - 1);
}

static int tegra_xhci_phy_init(struct platform_device *pdev)
{
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);
	struct phy *phy;
	int i, j, k, num;
	int ret;
	struct xusb_otg_port *otg_port;
	int usb3_otg_port_base_1 = 0;
	int usb2_otg_port_base_1 = 0;

	for (i = 0; i < MAX_PHY_TYPES; i++)
		tegra->num_phys += tegra->soc->num_typed_phys[i];

	tegra->phys = devm_kcalloc(&pdev->dev, tegra->num_phys, sizeof(phy),
				   GFP_KERNEL);

	if (tegra->soc->is_xhci_vf) {
		tegra->port_phy_map = devm_kcalloc(&pdev->dev, tegra->num_phys,
						sizeof(int), GFP_KERNEL);
	}

	if (!tegra->phys || (tegra->soc->is_xhci_vf && (!tegra->port_phy_map)))
		return -ENOMEM;

	for (i = 0; i < MAX_PHY_TYPES; i++) {
		if (i == 0) {
			tegra->typed_phys[0] = &tegra->phys[0];
			if (tegra->soc->is_xhci_vf)
				tegra->port_to_phy[0] = &tegra->port_phy_map[0];
		} else {
			tegra->typed_phys[i] = tegra->typed_phys[i - 1] +
					      tegra->soc->num_typed_phys[i - 1];
			if (tegra->soc->is_xhci_vf) {
				tegra->port_to_phy[i] =
					tegra->port_to_phy[i - 1] +
					tegra->soc->num_typed_phys[i - 1];
			}
		}

		k = 0;
		for (j = 0; j < tegra->soc->num_typed_phys[i]; j++) {
			char prop[16];

			if (tegra->soc->is_xhci_vf) {
				snprintf(prop, sizeof(prop), "vf%d-%s-%d",
					tegra->soc->vf_id,
					 tegra_xhci_phy_names[i], j);
			} else {
				snprintf(prop, sizeof(prop), "%s-%d",
					 tegra_xhci_phy_names[i], j);
			}

			phy = devm_phy_optional_get(&pdev->dev, prop);
			if (IS_ERR(phy)) {
				ret = PTR_ERR(phy);
				if (ret != -EPROBE_DEFER) {
					dev_warn(&pdev->dev,
						 "can't get %s phy (%d)\n",
						 prop, ret);
				}
				return ret;
			} else {
				if (phy && strstr(prop, "usb3") &&
				   tegra_xusb_padctl_has_otg_cap(tegra->padctl,
									phy)) {
					if (tegra->soc->is_xhci_vf)
						usb3_otg_port_base_1 = k + 1;
				}

				if (phy && strstr(prop, "usb2") &&
				   tegra_xusb_padctl_has_otg_cap(tegra->padctl,
								phy)) {
					if (tegra->soc->is_xhci_vf)
						usb2_otg_port_base_1 = k + 1;
				}

				if (phy && strstr(prop, "hsic"))
					tegra->num_hsic_port++;
			}

			if (!tegra->soc->is_xhci_vf) {
				tegra->typed_phys[i][j] = phy;
			} else {
				/* Storing the Phy's in the same order as
				 * port numbers as seen by the VF's
				 */
				if (phy != NULL) {
					tegra->typed_phys[i][k] = phy;
					tegra->port_to_phy[i][k] = j;
					k++;
				}
			}
		}
	}

	num = tegra_xusb_padctl_get_vbus_id_num(tegra->padctl);
	for (i = 0; i < num; i++) {
		int usb2_port, usb3_port;

		tegra_xusb_padctl_get_vbus_id_ports(tegra->padctl,
			i, &usb2_port, &usb3_port);
		tegra_xhci_init_otg_cap(tegra, i, usb2_port, usb3_port);
	}
	tegra->otg_port_num = num;

	/* multiple device mode not yet tested for VF because it needs
	 * changes in board to have VBUS extcon for second device mode.
	 */
	if (tegra->soc->is_xhci_vf && (tegra->otg_port_num > 1)) {
		otg_port = &tegra->otg_ports[0];
		otg_port->usb2_otg_port_base_1 = usb2_otg_port_base_1;
		otg_port->usb3_otg_port_base_1 = usb3_otg_port_base_1;
		tegra->otg_port_num = 1;
	}

	/* allocate optional cdp_ext_phys */
	tegra->cdp_ext_phys = devm_kcalloc(&pdev->dev,
					tegra->soc->num_typed_phys[USB2_PHY],
					sizeof(struct phy *), GFP_KERNEL);
	if (!tegra->cdp_ext_phys)
		return -ENOMEM;

	for (i = 0; i < tegra->soc->num_typed_phys[USB2_PHY]; i++) {
		char prop[8];

		/* get optional CDP phy */
		snprintf(prop, sizeof(prop),
			 "cdp-%d", i);
		phy = devm_phy_optional_get(
			  &pdev->dev, prop);
		if (!IS_ERR_OR_NULL(phy)) {
			dev_info(&pdev->dev,
				"External CDP phy %d registered\n",
				j);
			if (!tegra->soc->is_xhci_vf) {
				tegra->cdp_ext_phys[i] = phy;
			} else {
				for (j = 0; j <
				tegra->soc->num_typed_phys[USB2_PHY]; j++) {
					if (tegra->port_to_phy[USB2_PHY][j]
									== i)
						break;
				}
				/* Storing the CDP phys according to the port
				 * number index as seen by the VF
				 */
				tegra->cdp_ext_phys[j] = phy;
			}

			tegra->cdp_enabled = true;
		}
	}

	tegra->connected_usb2_ports = devm_kcalloc(&pdev->dev,
					tegra->soc->num_typed_phys[USB2_PHY],
					sizeof(u8), GFP_KERNEL);

	for (i = 0; i < tegra->otg_port_num; i++) {
		otg_port = &tegra->otg_ports[i];
		if (otg_port->usb2_otg_port_base_1)
			dev_info(&pdev->dev, "USB2 port %d has OTG_CAP\n",
				otg_port->usb2_otg_port_base_1 - 1);
		if (otg_port->usb3_otg_port_base_1)
			dev_info(&pdev->dev, "USB3 port %d has OTG_CAP\n",
				otg_port->usb3_otg_port_base_1 - 1);
	}
	if (tegra->otg_port_num == 0)
		dev_info(&pdev->dev, "No USB port has OTG_CAP\n");

	return 0;
}

static void tegra_xhci_oc_work(struct work_struct *work)
{
	struct tegra_xusb *tegra = container_of(work, struct tegra_xusb,
						oc_work);

	/* it will check every UTMI lanes to handle overcurrent events */
	tegra_xusb_padctl_handle_overcurrent(tegra->padctl);
}

static int tegra_sysfs_register(struct platform_device *pdev)
{
	int ret = 0;
	struct device *dev = NULL;
	struct tegra_xusb *tegra = NULL;

	if (pdev != NULL) {
		dev = &pdev->dev;
		tegra = platform_get_drvdata(pdev);
	}

	if (tegra && !tegra->xhci_err_init && dev != NULL) {
		ret = sysfs_create_group(&dev->kobj, &tegra_sysfs_group_errors);
		tegra->xhci_err_init = true;
	}

	if (ret) {
		pr_err("%s: failed to create tegra sysfs group %s\n",
			__func__, tegra_sysfs_group_errors.name);
	}

	return ret;
}

static ssize_t hsic_power_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);

	return sprintf(buf, "%d\n", tegra->hsic_power_on);
}

static ssize_t hsic_power_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);
	bool on;
	int rc;

	rc = kstrtobool(buf, &on);
	if (rc)
		return rc;
	rc = tegra_xusb_power(tegra, on);
	if (rc)
		return rc;
	return n;
}
static DEVICE_ATTR(hsic_power, 0644, hsic_power_show, hsic_power_store);

static struct attribute *tegra_xhci_attrs[] = {
	&dev_attr_hsic_power.attr,
	NULL,
};
static struct attribute_group tegra_xhci_attr_group = {
	.attrs = tegra_xhci_attrs,
};

static void tegra_xusb_deinit_extcon(struct tegra_xusb *tegra)
{
	int i;
	struct xusb_otg_port *otg_port;

	for (i = 0; i < tegra->otg_port_num; i++) {
		otg_port = &tegra->otg_ports[i];
		if (!IS_ERR(otg_port->edev)) {
			extcon_unregister_notifier(otg_port->edev,
					EXTCON_USB_HOST, &tegra->id_extcons_nb);
			otg_port->edev = NULL;
		}
	}
}

static int tegra_xusb_init_extcon(struct tegra_xusb *tegra)
{
	int err = 0, i;
	char edev_name[] = "idx";
	struct xusb_otg_port *port;

	INIT_WORK(&tegra->id_extcons_work, tegra_xhci_id_extcon_work);
	tegra->id_extcons_nb.notifier_call = tegra_xhci_id_notifier;

	for (i = 0; i < tegra->otg_port_num; i++) {
		struct extcon_dev *edev;

		port = &tegra->otg_ports[i];
		edev_name[2] = (i == 0) ? 0 : '0' + i;
		edev = extcon_get_extcon_dev_by_cable(tegra->dev, edev_name);
		if (!IS_ERR(edev)) {
			dev_info(tegra->dev, "extcon %d: %p %s\n", i,
				edev, edev_name);
			extcon_register_notifier(edev, EXTCON_USB_HOST,
					&tegra->id_extcons_nb);
			port->edev = edev;
		} else if (PTR_ERR(edev) == -EPROBE_DEFER) {
			err = -EPROBE_DEFER;
			goto exit;
		} else {
			dev_info(tegra->dev, "no USB ID extcon found: %s\n",
				edev_name);
			goto exit;
		}
	}
exit:
	if (err)
		tegra_xusb_deinit_extcon(tegra);

	return err;
}

static int tegra_xusb_probe(struct platform_device *pdev)
{
	struct resource *res, *regs;
	struct tegra_xusb *tegra;
	unsigned int i;
	int err;

	BUILD_BUG_ON(sizeof(struct tegra_xusb_fw_header) != 256);

	tegra = devm_kzalloc(&pdev->dev, sizeof(*tegra), GFP_KERNEL);
	if (!tegra)
		return -ENOMEM;

	tegra->soc = of_device_get_match_data(&pdev->dev);
	mutex_init(&tegra->lock);
	tegra->dev = &pdev->dev;
	platform_set_drvdata(pdev, tegra);

	tegra_xusb_parse_dt(pdev, tegra);

	if (tegra->boost_cpu_freq > 0) {
		dev_dbg(&pdev->dev, "PMQOS CPU freq boost enabled\n");
		tegra->cpu_boost_enabled = true;
	}

	/* If cpu boost is enabled, XHCI_BOOST_TRIGGER_SIZE is the
	 * minimum buffer length beyond which we boost the frequency.
	 */
	if (tegra->cpu_boost_enabled &&
			tegra->boost_cpu_trigger < XHCI_BOOST_TRIGGER_SIZE)
		tegra->boost_cpu_trigger = XHCI_BOOST_TRIGGER_SIZE;

	regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	tegra->regs = devm_ioremap_resource(&pdev->dev, regs);
	if (IS_ERR(tegra->regs))
		return PTR_ERR(tegra->regs);

	if (!tegra->soc->is_xhci_vf) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
		tegra->fpci_base = devm_ioremap_resource(&pdev->dev, res);

		if (IS_ERR(tegra->fpci_base))
			return PTR_ERR(tegra->fpci_base);

		tegra->fpci_start = res->start;
		tegra->fpci_len = resource_size(res);
	}

	if (tegra->soc->has_ipfs) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
		tegra->ipfs_base = devm_ioremap_resource(&pdev->dev, res);
		if (IS_ERR(tegra->ipfs_base))
			return PTR_ERR(tegra->ipfs_base);
	}

	if (!tegra->soc->is_xhci_vf) {
#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
		tegra->pgid_ss = tegra_pd_get_powergate_id(tegra_xusba_pd);
#else
		tegra->pgid_ss = TEGRA_POWERGATE_XUSBA;
#endif
		if (tegra->pgid_ss < 0) {
			dev_err(&pdev->dev, "failed to get SS powergate id\n");
			return tegra->pgid_ss;
		}

#if IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS)
		tegra->pgid_host = tegra_pd_get_powergate_id(tegra_xusbc_pd);
#else
		tegra->pgid_host = TEGRA_POWERGATE_XUSBC
#endif
		if (tegra->pgid_host < 0) {
			dev_err(&pdev->dev,
				"failed to get Host powergate id\n");
			return tegra->pgid_host;
		}
	}

	tegra->xhci_irq = platform_get_irq(pdev, 0);
	if (tegra->xhci_irq < 0)
		return tegra->xhci_irq;

	if (!tegra->soc->is_xhci_vf) {
		tegra->mbox_irq = platform_get_irq(pdev, 1);
		if (tegra->mbox_irq < 0)
			return tegra->mbox_irq;

		tegra->padctl_irq = platform_get_irq(pdev, 2);
		if (tegra->padctl_irq < 0)
			return tegra->padctl_irq;
	}

	tegra->padctl = tegra_xusb_padctl_get(&pdev->dev);
	if (IS_ERR(tegra->padctl))
		return PTR_ERR(tegra->padctl);

	if (XHCI_IS_T194(tegra) && !tegra->soc->is_xhci_vf) {

		tegra->core_superspeed_clk = devm_clk_get(&pdev->dev,
						"xusb_core_superspeed_clk");
		if (IS_ERR(tegra->core_superspeed_clk)) {
			err = PTR_ERR(tegra->core_superspeed_clk);
			dev_err(&pdev->dev, "failed to get xusb_core_superspeed: %d\n",
					err);
			goto put_padctl;
		}

		tegra->falcon_host_clk = devm_clk_get(&pdev->dev,
						"xusb_falcon_host_clk");
		if (IS_ERR(tegra->falcon_host_clk)) {
			err = PTR_ERR(tegra->falcon_host_clk);
			dev_err(&pdev->dev, "failed to get xusb_falcon_host: %d\n",
					err);
			goto put_padctl;
		}

		tegra->falcon_superspeed_clk = devm_clk_get(&pdev->dev,
						"xusb_falcon_superspeed_clk");
		if (IS_ERR(tegra->falcon_superspeed_clk)) {
			err = PTR_ERR(tegra->falcon_superspeed_clk);
			dev_err(&pdev->dev, "failed to get xusb_falcon_superspeed: %d\n",
					err);
			goto put_padctl;
		}

		tegra->fs_host_clk = devm_clk_get(&pdev->dev,
						"xusb_fs_host_clk");
		if (IS_ERR(tegra->fs_host_clk)) {
			err = PTR_ERR(tegra->fs_host_clk);
			dev_err(&pdev->dev, "failed to get xusb_fs_host: %d\n",
					err);
			goto put_padctl;
		}
	}

	if (!tegra->soc->is_xhci_vf) {
		tegra->host_clk = devm_clk_get(&pdev->dev, "xusb_host");
		if (IS_ERR(tegra->host_clk)) {
			err = PTR_ERR(tegra->host_clk);
			dev_err(&pdev->dev, "failed to get xusb_host: %d\n",
					err);
			goto put_padctl;
		}

		tegra->falcon_clk = devm_clk_get(&pdev->dev, "xusb_falcon_src");
		if (IS_ERR(tegra->falcon_clk)) {
			err = PTR_ERR(tegra->falcon_clk);
			dev_err(&pdev->dev,
				"failed to get xusb_falcon_src: %d\n", err);
			goto put_padctl;
		}

		tegra->ss_clk = devm_clk_get(&pdev->dev, "xusb_ss");
		if (IS_ERR(tegra->ss_clk)) {
			err = PTR_ERR(tegra->ss_clk);
			dev_err(&pdev->dev, "failed to get xusb_ss: %d\n", err);
			goto put_padctl;
		}

		tegra->ss_src_clk = devm_clk_get(&pdev->dev, "xusb_ss_src");
		if (IS_ERR(tegra->ss_src_clk)) {
			err = PTR_ERR(tegra->ss_src_clk);
			dev_err(&pdev->dev, "failed to get xusb_ss_src: %d\n",
					err);
			goto put_padctl;
		}

		tegra->hs_src_clk = devm_clk_get(&pdev->dev, "xusb_hs_src");
		if (IS_ERR(tegra->hs_src_clk)) {
			err = PTR_ERR(tegra->hs_src_clk);
			dev_err(&pdev->dev, "failed to get xusb_hs_src: %d\n",
					err);
			goto put_padctl;
		}

		tegra->fs_src_clk = devm_clk_get(&pdev->dev, "xusb_fs_src");
		if (IS_ERR(tegra->fs_src_clk)) {
			err = PTR_ERR(tegra->fs_src_clk);
			dev_err(&pdev->dev, "failed to get xusb_fs_src: %d\n",
					err);
			goto put_padctl;
		}

		tegra->pll_u_480m = devm_clk_get(&pdev->dev, "pll_u_480m");
		if (IS_ERR(tegra->pll_u_480m)) {
			err = PTR_ERR(tegra->pll_u_480m);
			dev_err(&pdev->dev, "failed to get pll_u_480m: %d\n",
					err);
			goto put_padctl;
		}

		tegra->clk_m = devm_clk_get(&pdev->dev, "clk_m");
		if (IS_ERR(tegra->clk_m)) {
			err = PTR_ERR(tegra->clk_m);
			dev_err(&pdev->dev, "failed to get clk_m: %d\n", err);
			goto put_padctl;
		}

		tegra->pll_e = devm_clk_get(&pdev->dev, "pll_e");
		if (IS_ERR(tegra->pll_e)) {
			err = PTR_ERR(tegra->pll_e);
			dev_err(&pdev->dev, "failed to get pll_e: %d\n", err);
			goto put_padctl;
		}

		tegra->supplies = devm_kcalloc(&pdev->dev,
				tegra->soc->num_supplies,
				sizeof(*tegra->supplies), GFP_KERNEL);
		if (!tegra->supplies) {
			err = -ENOMEM;
			goto put_padctl;
		}

		for (i = 0; i < tegra->soc->num_supplies; i++)
			tegra->supplies[i].supply = tegra->soc->supply_names[i];

		err = devm_regulator_bulk_get(&pdev->dev,
				tegra->soc->num_supplies, tegra->supplies);
		if (err) {
			dev_err(&pdev->dev, "failed to get regulators: %d\n",
					err);
			goto put_padctl;
		}
	}

	err = tegra_xhci_phy_init(pdev);
	if (err)
		goto put_padctl;

	if (!tegra->soc->is_xhci_vf) {
		err = tegra_xusb_clk_enable(tegra);
		if (err) {
			dev_err(&pdev->dev, "failed to enable clocks: %d\n",
					err);
			goto put_padctl;
		}

		err = regulator_bulk_enable(tegra->soc->num_supplies,
				tegra->supplies);
		if (err) {
			dev_err(&pdev->dev, "failed to enable regulators: %d\n",
					err);
			goto disable_clk;
		}
	}

	err = tegra_xusb_phy_enable(tegra);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to enable PHYs: %d\n", err);
		goto disable_regulator;
	}

	if (!tegra->soc->is_xhci_vf) {
		err = tegra_xhci_unpowergate_partitions(tegra);
		if (err) {
			dev_err(&pdev->dev, "failed to unpowergate (%d)\n",
					err);
			goto disable_phy;
		}
	}

	if (!tegra->soc->is_xhci_vf)
		tegra_xusb_config(tegra);

	tegra_xusb_debugfs_init(tegra);
	tegra_sysfs_register(pdev);

	if (tegra->soc->disable_hsic_wake)
		tegra_xusb_disable_hsic_wake(tegra);

	if (tegra_platform_is_silicon() && tegra->otg_port_num) {
		err = tegra_xusb_init_extcon(tegra);
		if (err)
			goto powergate_partitions;
	}

	err = sysfs_create_file(&pdev->dev.kobj, &dev_attr_downgrade_usb3.attr);
	if (err) {
		dev_err(&pdev->dev,
			"failed to create tegra sysfs file downgrade_usb3\n");
		goto unregister_extcon;
	}

	if (tegra->soc->is_xhci_vf) {
		tegra_xusb_probe_finish(NULL, tegra);
	} else {
		INIT_DELAYED_WORK(&tegra->firmware_retry_work,
						tegra_firmware_retry_work);

		err = request_firmware_nowait(THIS_MODULE, true,
					      tegra->soc->firmware,
					      tegra->dev, GFP_KERNEL, tegra,
					      tegra_xusb_probe_finish);
		if (err < 0) {
			dev_err(&pdev->dev, "can't request firmware(%d)\n",
				err);
			goto err_create_sysfs;
		}
	}

	if (tegra->soc->handle_oc)
		INIT_WORK(&tegra->oc_work, tegra_xhci_oc_work);

	/* Init pm qos for cpu boost */
	if (tegra->cpu_boost_enabled)
		tegra_xusb_boost_cpu_init(tegra);

	err = sysfs_create_group(&pdev->dev.kobj, &tegra_xhci_attr_group);
	if (err) {
		dev_err(&pdev->dev, "cannot create sysfs group: %d\n", err);
		goto err_create_sysfs;
	}

	/* TODO: look up dtb */
	device_init_wakeup(tegra->dev, true);

	return 0;

err_create_sysfs:
	sysfs_remove_file(&pdev->dev.kobj, &dev_attr_downgrade_usb3.attr);
unregister_extcon:
	if (tegra_platform_is_silicon() && tegra->otg_port_num) {
		cancel_work_sync(&tegra->id_extcons_work);
		tegra_xusb_deinit_extcon(tegra);
	}
powergate_partitions:
	if (tegra->xhci_err_init && tegra->dev != NULL) {
		sysfs_remove_group(&tegra->dev->kobj,
				&tegra_sysfs_group_errors);
		tegra->xhci_err_init = false;
	}
	tegra_xusb_debugfs_deinit(tegra);
	if (!tegra->soc->is_xhci_vf)
		tegra_xhci_powergate_partitions(tegra);
disable_phy:
	tegra_xusb_phy_disable(tegra);
disable_regulator:
	if (!tegra->soc->is_xhci_vf)
		regulator_bulk_disable(tegra->soc->num_supplies,
				tegra->supplies);
disable_clk:
	if (!tegra->soc->is_xhci_vf)
		tegra_xusb_clk_disable(tegra);
put_padctl:
	tegra_xusb_padctl_put(tegra->padctl);
	return err;
}

static void tegra_xusb_shutdown(struct platform_device *pdev)
{
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);

	if (!tegra)
		return;

	if (!tegra->fw_loaded && !tegra->soc->is_xhci_vf)
		return;

	pm_runtime_get_sync(tegra->dev);

	if (tegra->hcd)
		xhci_shutdown(tegra->hcd);
}

static int tegra_xusb_remove(struct platform_device *pdev)
{
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	if (tegra->xhci_err_init && dev != NULL) {
		sysfs_remove_group(&dev->kobj, &tegra_sysfs_group_errors);
		tegra->xhci_err_init = false;
	}

	if (tegra->soc->handle_oc)
		cancel_work_sync(&tegra->oc_work);

	if (tegra->soc->is_xhci_vf)
		cancel_work_sync(&tegra->ivc_work);

	if (tegra->cpu_boost_enabled)
		tegra_xusb_boost_cpu_deinit(tegra);

	if (tegra_platform_is_silicon() && tegra->otg_port_num) {
		cancel_work_sync(&tegra->id_extcons_work);
		tegra_xusb_deinit_extcon(tegra);
	}

	sysfs_remove_file(&pdev->dev.kobj, &dev_attr_downgrade_usb3.attr);

	if (!tegra->soc->is_xhci_vf)
		cancel_delayed_work_sync(&tegra->firmware_retry_work);

	pm_runtime_get_sync(tegra->dev);
	device_remove_file(&pdev->dev, &dev_attr_reload_hcd);

	if (!IS_ERR(tegra->fwdev))
		devm_tegrafw_unregister(dev, tegra->fwdev);

	sysfs_remove_group(&pdev->dev.kobj, &tegra_xhci_attr_group);

	if (tegra->soc->is_xhci_vf && (tegra->ivck != NULL)) {
		tegra_hv_ivc_unreserve(tegra->ivck);
		devm_free_irq(dev, tegra->ivck->irq, tegra);
	}

	if (tegra->fw_loaded || tegra->soc->is_xhci_vf) {
		struct xhci_hcd *xhci = hcd_to_xhci(tegra->hcd);

		usb_remove_hcd(xhci->shared_hcd);
		usb_put_hcd(xhci->shared_hcd);
		usb_remove_hcd(tegra->hcd);

		disable_irq(tegra->xhci_irq);
		disable_irq(tegra->padctl_irq);
		disable_irq(tegra->mbox_irq);

		devm_iounmap(&pdev->dev, tegra->fpci_base);
		devm_release_mem_region(&pdev->dev, tegra->fpci_start,
			tegra->fpci_len);

		devm_iounmap(&pdev->dev, tegra->hcd->regs);
		devm_release_mem_region(&pdev->dev, tegra->hcd->rsrc_start,
			tegra->hcd->rsrc_len);
		usb_put_hcd(tegra->hcd);
	}

	if (!tegra->soc->is_xhci_vf) {
		dma_free_coherent(&pdev->dev, tegra->fw.size, tegra->fw.virt,
				  tegra->fw.phys);

		fw_log_deinit(tegra);
	}

	tegra_xusb_phy_disable(tegra);
	if (!tegra->soc->is_xhci_vf) {
		regulator_bulk_disable(tegra->soc->num_supplies,
				tegra->supplies);

		tegra_xusb_clk_disable(tegra);

		tegra_xhci_powergate_partitions(tegra);
	}

	tegra_xusb_padctl_put(tegra->padctl);

	pm_runtime_disable(tegra->dev);
	pm_runtime_put(tegra->dev);

	if (!tegra->soc->is_xhci_vf) {
		devm_free_irq(&pdev->dev, tegra->padctl_irq, tegra);
		devm_free_irq(&pdev->dev, tegra->mbox_irq, tegra);
	}

	tegra_xusb_host_vbus_power_off(tegra);

	tegra_xusb_debugfs_deinit(tegra);

	return 0;
}

#if IS_ENABLED(CONFIG_PM_SLEEP) || IS_ENABLED(CONFIG_PM)
static void tegra_xhci_save_context(struct tegra_xusb *tegra)
{
	if (tegra->soc->has_ipfs) {
		/* Save IPFS registers */
		tegra->ipfs_ctx.msi_bar_sz =
				ipfs_readl(tegra, XUSB_HOST_MSI_BAR_SZ_0);
		tegra->ipfs_ctx.msi_axi_barst =
				ipfs_readl(tegra, XUSB_HOST_MSI_AXI_BAR_ST_0);
		tegra->ipfs_ctx.msi_fpci_barst =
				ipfs_readl(tegra, XUSB_HOST_MSI_FPCI_BAR_ST_0);
		tegra->ipfs_ctx.msi_vec0 =
				ipfs_readl(tegra, XUSB_HOST_MSI_VEC0_0);
		tegra->ipfs_ctx.msi_en_vec0 =
				ipfs_readl(tegra, XUSB_HOST_MSI_EN_VEC0_0);
		tegra->ipfs_ctx.fpci_error_masks =
				ipfs_readl(tegra, XUSB_HOST_FPCI_ERROR_MASKS_0);
		tegra->ipfs_ctx.intr_mask =
				ipfs_readl(tegra, XUSB_HOST_INTR_MASK_0);
		tegra->ipfs_ctx.ipfs_intr_enable =
				ipfs_readl(tegra, XUSB_HOST_IPFS_INTR_ENABLE_0);
		tegra->ipfs_ctx.ufpci_config =
				ipfs_readl(tegra, XUSB_HOST_UFPCI_CONFIG_0);
		tegra->ipfs_ctx.clkgate_hysteresis =
				ipfs_readl(tegra,
					XUSB_HOST_CLKGATE_HYSTERESIS_0);
		tegra->ipfs_ctx.xusb_host_mccif_fifo_cntrl =
				ipfs_readl(tegra, XUSB_HOST_MCCIF_FIFOCTRL_0);
	}

	/* Save FPCI registers */
	tegra->fpci_ctx.hs_pls =
		fpci_readl(tegra, XUSB_CFG_ARU_CONTEXT_HS_PLS);
	tegra->fpci_ctx.fs_pls =
		fpci_readl(tegra, XUSB_CFG_ARU_CONTEXT_FS_PLS);
	tegra->fpci_ctx.hsfs_speed =
		fpci_readl(tegra, XUSB_CFG_ARU_CONTEXT_HSFS_SPEED);
	tegra->fpci_ctx.hsfs_pp =
		fpci_readl(tegra, XUSB_CFG_ARU_CONTEXT_HSFS_PP);
	tegra->fpci_ctx.cfg_aru = fpci_readl(tegra, XUSB_CFG_ARU_CONTEXT);
	tegra->fpci_ctx.cfg_order = fpci_readl(tegra, XUSB_CFG_AXI_CFG);
	tegra->fpci_ctx.cfg_fladj = fpci_readl(tegra, XUSB_CFG_24);
	tegra->fpci_ctx.cfg_sid = fpci_readl(tegra, XUSB_CFG_16);
}

static void tegra_xhci_restore_context(struct tegra_xusb *tegra)
{
	/* Restore FPCI registers */
	fpci_writel(tegra, tegra->fpci_ctx.hs_pls, XUSB_CFG_ARU_CONTEXT_HS_PLS);
	fpci_writel(tegra, tegra->fpci_ctx.fs_pls, XUSB_CFG_ARU_CONTEXT_FS_PLS);
	fpci_writel(tegra, tegra->fpci_ctx.hsfs_speed,
		    XUSB_CFG_ARU_CONTEXT_HSFS_SPEED);
	fpci_writel(tegra, tegra->fpci_ctx.hsfs_pp,
		    XUSB_CFG_ARU_CONTEXT_HSFS_PP);
	fpci_writel(tegra, tegra->fpci_ctx.cfg_aru, XUSB_CFG_ARU_CONTEXT);
	fpci_writel(tegra, tegra->fpci_ctx.cfg_order, XUSB_CFG_AXI_CFG);
	fpci_writel(tegra, tegra->fpci_ctx.cfg_fladj, XUSB_CFG_24);
	fpci_writel(tegra, tegra->fpci_ctx.cfg_sid, XUSB_CFG_16);

	if (tegra->soc->has_ipfs) {
		/* Restore IPFS registers */
		ipfs_writel(tegra, tegra->ipfs_ctx.msi_bar_sz,
				XUSB_HOST_MSI_BAR_SZ_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.msi_axi_barst,
				XUSB_HOST_MSI_AXI_BAR_ST_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.msi_fpci_barst,
				XUSB_HOST_MSI_FPCI_BAR_ST_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.msi_vec0,
				XUSB_HOST_MSI_VEC0_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.msi_en_vec0,
				XUSB_HOST_MSI_EN_VEC0_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.fpci_error_masks,
				XUSB_HOST_FPCI_ERROR_MASKS_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.intr_mask,
				XUSB_HOST_INTR_MASK_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.ipfs_intr_enable,
				XUSB_HOST_IPFS_INTR_ENABLE_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.ufpci_config,
				XUSB_HOST_UFPCI_CONFIG_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.clkgate_hysteresis,
				XUSB_HOST_CLKGATE_HYSTERESIS_0);
		ipfs_writel(tegra, tegra->ipfs_ctx.xusb_host_mccif_fifo_cntrl,
				XUSB_HOST_MCCIF_FIFOCTRL_0);
	}
}

static inline u32 read_portsc(struct tegra_xusb *tegra, unsigned int port)
{
	struct xhci_hcd *xhci = hcd_to_xhci(tegra->hcd);

	return readl(&xhci->op_regs->port_status_base + NUM_PORT_REGS * port);
}

static void get_rootport_name(struct tegra_xusb *tegra, int i,
		char *name, int size)
{
	struct xhci_hcd *xhci = hcd_to_xhci(tegra->hcd);
	const struct tegra_xusb_soc *soc = tegra->soc;
	struct usb_hcd *hcd = NULL;
	int dev_id = -1;

	if ((i >= soc->ports.usb3.offset) &&
		(i < (soc->ports.usb3.offset + soc->ports.usb3.count))) {
		hcd = xhci->shared_hcd;
		dev_id = i - soc->ports.usb3.offset + 1;
	} else if ((i >= soc->ports.usb2.offset) &&
		(i < (soc->ports.usb2.offset + soc->ports.usb2.count +
		soc->ports.hsic.count))) {
		hcd = xhci->main_hcd;
		dev_id = i - soc->ports.usb2.offset + 1;
	}

	memset(name, 0, size);
	if (hcd)
		snprintf(name, size, "%d-%d", hcd->self.busnum, dev_id);
	else
		snprintf(name, size, "port %d", i);
}

static enum usb_device_speed port_speed(struct tegra_xusb *tegra,
					unsigned int port)
{
	u32 portsc = read_portsc(tegra, port);

	if (DEV_FULLSPEED(portsc))
		return USB_SPEED_FULL;
	else if (DEV_HIGHSPEED(portsc))
		return USB_SPEED_HIGH;
	else if (DEV_LOWSPEED(portsc))
		return USB_SPEED_LOW;
	else if (DEV_SUPERSPEED(portsc))
		return USB_SPEED_SUPER;
	else
		return USB_SPEED_UNKNOWN;
}

static void tegra_xhci_enable_phy_sleepwalk_wake(struct tegra_xusb *tegra)
{
	struct tegra_xusb_padctl *padctl = tegra->padctl;
	enum usb_device_speed speed;
	struct phy *phy;
	int offset;
	int i, j;

	for (i = 0; i < MAX_PHY_TYPES; i++) {
		if (i == USB3_PHY)
			offset = tegra->soc->ports.usb3.offset;

		if (i == USB2_PHY)
			offset = tegra->soc->ports.usb2.offset;

		if (i == HSIC_PHY)
			offset = tegra->soc->ports.hsic.offset;

		for (j = 0; j < tegra->soc->num_typed_phys[i]; j++) {
			phy = tegra->typed_phys[i][j];

			if (!phy)
				continue;

			if (!is_host_mode_phy(tegra, i, j))
				continue;

			speed = port_speed(tegra, offset + j);
			tegra_xusb_padctl_enable_phy_sleepwalk(padctl, phy,
							       speed);
			tegra_xusb_padctl_enable_phy_wake(padctl, phy);
		}
	}
}

static void tegra_xhci_disable_phy_wake(struct tegra_xusb *tegra)
{
	struct tegra_xusb_padctl *padctl = tegra->padctl;
	struct phy *phy;
	int i, j;

	for (i = 0; i < MAX_PHY_TYPES; i++) {
		for (j = 0; j < tegra->soc->num_typed_phys[i]; j++) {
			phy = tegra->typed_phys[i][j];

			if (!phy)
				continue;

			if (tegra_xusb_padctl_remote_wake_detected(
							padctl, phy)) {
				dev_dbg(tegra->dev, "%s port %d remote wake detected\n"
					, tegra_xhci_phy_names[i], j);
				if (i == USB2_PHY)
					tegra_phy_xusb_utmi_pad_power_on(phy);
			}
			tegra_xusb_padctl_disable_phy_wake(padctl, phy);
		}
	}
}

static void tegra_xhci_disable_phy_sleepwalk(struct tegra_xusb *tegra)
{
	struct tegra_xusb_padctl *padctl = tegra->padctl;
	struct phy *phy;
	int i, j;

	for (i = 0; i < MAX_PHY_TYPES; i++) {
		for (j = 0; j < tegra->soc->num_typed_phys[i]; j++) {
			phy = tegra->typed_phys[i][j];

			if (!phy)
				continue;

			tegra_xusb_padctl_disable_phy_sleepwalk(padctl, phy);
		}
	}
}

static void tegra_xhci_program_utmi_power_lp0_exit(
	struct tegra_xusb *tegra)
{
	int i;

	for (i = 0; i < tegra->soc->num_typed_phys[USB2_PHY]; i++) {
		if (!is_host_mode_phy(tegra, USB2_PHY, i))
			continue;

		if (tegra->enable_utmi_pad_after_lp0_exit & BIT(i))
			tegra_phy_xusb_utmi_pad_power_on(
					tegra->typed_phys[USB2_PHY][i]);
		else
			tegra_phy_xusb_utmi_pad_power_down(
					tegra->typed_phys[USB2_PHY][i]);
	}
}

static int tegra_xhci_wait_for_ports_enter_u3(struct tegra_xusb *tegra)
{
	struct xhci_hcd *xhci = hcd_to_xhci(tegra->hcd);
	struct device *dev = tegra->dev;
	u32 usbcmd;
	int i;
	int num_ports = HCS_MAX_PORTS(xhci->hcs_params1);
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&xhci->lock, flags);

	usbcmd = readl(&xhci->op_regs->command);
	usbcmd &= ~CMD_EIE;
	writel(usbcmd, &xhci->op_regs->command);

	for (i = 0; i < num_ports; i++) {
		bool is_busy = true;
		char devname[16];
		u32 portsc = read_portsc(tegra, i);

		if (!(portsc & PORT_PE))
			continue;

		if ((portsc & PORT_PLS_MASK) == XDEV_U3)
			continue;

		get_rootport_name(tegra, i, devname, sizeof(devname));

		if (tegra->soc->ss_lfps_detector_war &&
			DEV_SUPERSPEED(portsc)) {
			unsigned long end = jiffies + msecs_to_jiffies(200);

			while (time_before(jiffies, end)) {
				if ((portsc & PORT_PLS_MASK) == XDEV_RESUME)
					break;
				spin_unlock_irqrestore(&xhci->lock, flags);
				msleep(20);
				spin_lock_irqsave(&xhci->lock, flags);

				portsc = read_portsc(tegra, i);
				if ((portsc & PORT_PLS_MASK) == XDEV_U3) {
					dev_info(dev, "%s is suspended\n",
							devname);
					is_busy = false;
					break;
				}
			}
		}

		if (is_busy) {
			dev_info(dev, "%s is not suspended: %08x\n", devname,
					portsc);
			ret = -EBUSY;
			break;
		}

		dev_info(dev, "%s is not suspended: %08x\n", devname,
			portsc);
		ret = -EBUSY;
		break;
	}

	spin_unlock_irqrestore(&xhci->lock, flags);

	return ret;
}

/* caller must hold tegra->lock */
static int tegra_xhci_enter_elpg(struct tegra_xusb *tegra, bool runtime)
{
	struct xhci_hcd *xhci = hcd_to_xhci(tegra->hcd);
	struct device *dev = tegra->dev;
	bool do_wakeup = runtime ? true : device_may_wakeup(dev);
	unsigned int i, j;
	u32 portsc;
	int ret;

	dev_info(dev, "entering ELPG\n");

	/* Wait for ports to enter U3. */
	ret = tegra_xhci_wait_for_ports_enter_u3(tegra);
	if (ret < 0)
		goto out;

	for (i = 0; i < xhci->num_usb2_ports; i++) {
		portsc = readl(xhci->usb2_ports[i]);
		tegra->enable_utmi_pad_after_lp0_exit &= ~BIT(i);

		if (((portsc & PORT_PLS_MASK) == XDEV_U3) ||
			((portsc & DEV_SPEED_MASK) == XDEV_FS))
			tegra->enable_utmi_pad_after_lp0_exit |= BIT(i);
	}

	ret = xhci_suspend(xhci, do_wakeup);

	if (ret) {
		dev_warn(dev, "xhci_suspend() failed %d\n", ret);
		goto out;
	}

	if (!tegra->soc->is_xhci_vf)
		tegra_xhci_save_context(tegra);

	if (do_wakeup)
		tegra_xhci_enable_phy_sleepwalk_wake(tegra);

	if (!tegra->soc->is_xhci_vf) {
		/* In ELPG, firmware log context is gone. Rewind shared log buffer. */
		if (test_bit(FW_LOG_CONTEXT_VALID, &tegra->log.flags)) {
			if (!circ_buffer_full(&tegra->log.circ)) {
				if (fw_log_wait_empty_timeout(tegra, 500))
					dev_info(dev, "%s still has logs\n",
						__func__);
			}

			tegra->log.dequeue = tegra->log.virt_addr;
			tegra->log.seq = 0;
		}

		ret = tegra_xhci_powergate_partitions(tegra);
		if (ret) {
			dev_warn(dev, "failed to powergate Host partition %d\n",
				ret);
			goto out;
		}
	}

	if (!do_wakeup)
		tegra_xusb_host_vbus_power_off(tegra);

	for (i = 0; i < MAX_PHY_TYPES; i++) {
		for (j = 0; j < tegra->soc->num_typed_phys[i]; j++) {
			struct phy *phy = tegra->typed_phys[i][j];

			if (!phy)
				continue;

			if (i == USB2_PHY && is_host_mode_phy(tegra, i, j))
				tegra_phy_xusb_utmi_pad_power_down(phy);

			phy_power_off(phy);
			if (!do_wakeup)
				phy_exit(phy);
		}
	}

	if (!tegra->soc->is_xhci_vf)
		tegra_xusb_clk_disable(tegra);

out:
	if (!ret)
		dev_info(tegra->dev, "entering ELPG done\n");
	else {
		u32 usbcmd;

		usbcmd = readl(&xhci->op_regs->command);
		usbcmd |= CMD_EIE;
		writel(usbcmd, &xhci->op_regs->command);

		dev_info(tegra->dev, "entering ELPG failed\n");
	}

	return ret;
}

/* caller must hold tegra->lock */
static int tegra_xhci_exit_elpg(struct tegra_xusb *tegra, bool runtime)
{
	struct xhci_hcd *xhci = hcd_to_xhci(tegra->hcd);
	struct device *dev = tegra->dev;
	struct tegra_xusb_mbox_msg msg;
	bool do_wakeup = runtime ? true : device_may_wakeup(dev);
	unsigned int i, j;
	int ret;
	u32 usbcmd;

	dev_info(dev, "exiting ELPG\n");

	if (!tegra->soc->is_xhci_vf) {
		ret = tegra_xusb_clk_enable(tegra);
		if (ret) {
			dev_warn(dev, "failed to enable xhci clocks %d\n", ret);
			goto out;
		}
	}

	if (!tegra->soc->is_xhci_vf) {
		ret = tegra_xhci_unpowergate_partitions(tegra);
		if (ret < 0) {
			dev_warn(dev, "failed to unpowergate partitions %d\n",
					ret);
			goto out;
		}
	}

	if (do_wakeup)
		tegra_xhci_disable_phy_wake(tegra);

	if (tegra->hsic_power_on)
		tegra_xusb_padctl_hsic_set_idle(tegra->padctl, 0, true);

	for (i = 0; i < MAX_PHY_TYPES; i++) {
		for (j = 0; j < tegra->soc->num_typed_phys[i]; j++) {

			if (!do_wakeup) {
				ret = phy_init(tegra->typed_phys[i][j]);
				if (ret) {
					dev_err(dev, "phy_init failed:%d\n",
						ret);
					goto out;
				}
			}
			ret = phy_power_on(tegra->typed_phys[i][j]);
			if (ret) {
				dev_err(dev, "phy_power_on failed:%d\n", ret);
				goto out;
			}
		}
	}

	/* ID override to ground needs to be set after VCORE_DOWN is 0 */
	for (i = 0; i < tegra->otg_port_num; i++) {
		struct xusb_otg_port *port;

		port = &tegra->otg_ports[i];
		if (!port->host_mode)
			continue;
		tegra_xusb_padctl_set_id_override(tegra->padctl, i);
	}

	if (tegra->suspended)
		tegra_xhci_program_utmi_power_lp0_exit(tegra);

	if (!tegra->soc->is_xhci_vf) {
		tegra_xusb_config(tegra);

		if (tegra->soc->disable_hsic_wake)
			tegra_xusb_disable_hsic_wake(tegra);

		tegra_xhci_restore_context(tegra);

		ret = tegra_xhci_load_firmware(tegra);
		if (ret < 0)
			goto out;

		msg.cmd = MBOX_CMD_MSG_ENABLED;
		msg.data = 0;

		ret = tegra_xusb_mbox_send(tegra, &msg);
		if (ret < 0) {
			dev_err(dev, "failed to enable messages: %d\n", ret);
			goto out;
		}
	}

	if (!do_wakeup)
		tegra_xusb_host_vbus_power_on(tegra);

	if (do_wakeup)
		tegra_xhci_disable_phy_sleepwalk(tegra);

	ret = xhci_resume(xhci, 0);

	usbcmd = readl(&xhci->op_regs->command);
	usbcmd |= CMD_EIE;
	writel(usbcmd, &xhci->op_regs->command);

out:
	if (!ret)
		dev_info(dev, "exiting ELPG done\n");
	else
		dev_info(dev, "exiting ELPG failed\n");

	return ret;
}
#endif /* IS_ENABLED(CONFIG_PM_SLEEP) || IS_ENABLED(CONFIG_PM) */


static inline int set_cdp_enable(struct tegra_xusb *tegra,
					int port_idx, bool enable)
{
	int ret;
	dev_info(tegra->dev, "%sable %sternal cdp %d\n",
		enable ? "en" : "dis",
		tegra->cdp_internal ? "in" : "ex",
		port_idx);
	if (enable) {
		if (tegra->cdp_internal)
			tegra_xusb_padctl_enable_host_cdp(tegra->padctl,
				tegra->typed_phys[USB2_PHY][port_idx]);
		else {
			ret = phy_power_on(tegra->cdp_ext_phys[port_idx]);
			if (ret)
				dev_err(tegra->dev, "phy_power_on failed");
		}
	} else {
		if (tegra->cdp_internal)
			tegra_xusb_padctl_disable_host_cdp(tegra->padctl,
				tegra->typed_phys[USB2_PHY][port_idx]);
		else
			phy_power_off(tegra->cdp_ext_phys[port_idx]);
	}
	return 0;
}


#if IS_ENABLED(CONFIG_PM_SLEEP)
static int tegra_xusb_suspend(struct device *dev)
{
	struct tegra_xusb *tegra = dev_get_drvdata(dev);
	struct xhci_hcd *xhci;
	int ret;
	unsigned int j;

	if (!tegra->fw_loaded && !tegra->soc->is_xhci_vf)
		return 0;

	xhci = hcd_to_xhci(tegra->hcd);

	if (xhci->recovery_in_progress == true)
		return 0;

	if (tegra->soc->handle_oc)
		flush_work(&tegra->oc_work);

	if (tegra->soc->is_xhci_vf)
		flush_work(&tegra->ivc_work);

	mutex_lock(&tegra->lock);

	if (pm_runtime_suspended(dev)) {
		ret = tegra_xhci_exit_elpg(tegra, true);
		if (ret < 0)
			goto out;
	}

	ret = tegra_xhci_enter_elpg(tegra, false);
	if (ret < 0) {
		if (pm_runtime_suspended(dev)) {
			pm_runtime_disable(dev);
			pm_runtime_set_active(dev);
			pm_runtime_enable(dev);
		}

		goto out;
	}

	/* disable CDP for all ports */
	if (tegra->cdp_enabled) {
		for (j = 0; j < tegra->soc->num_typed_phys[USB2_PHY]; j++) {
			set_cdp_enable(tegra, j, false);

			if (!tegra->typed_phys[USB2_PHY][j])
				continue;
			/*
			 * turn off VBUS for CDP enabled case.
			 * skip vbus off for OTG port when it isn't host role
			 */
			if (is_host_mode_phy(tegra, USB2_PHY, j)) {
				int port = j;

				if (tegra->soc->is_xhci_vf)
					port = tegra->port_to_phy[USB2_PHY][j];

				tegra_xusb_padctl_vbus_power_off(
					tegra->padctl, port);
			}
		}
	}

out:
	if (!ret) {
		tegra->suspended = true;
		if (!tegra->soc->is_xhci_vf && device_may_wakeup(dev)) {
			if (enable_irq_wake(tegra->padctl_irq))
				dev_err(dev,
				"failed to enable padctl wakes\n");
		}
		pm_runtime_disable(dev);
	}

	mutex_unlock(&tegra->lock);

	return ret;
}

static int tegra_xhci_resume_common(struct device *dev)
{
	struct tegra_xusb *tegra = dev_get_drvdata(dev);
	int ret;
	unsigned int j;

	mutex_lock(&tegra->lock);
	if (!tegra->suspended) {
		mutex_unlock(&tegra->lock);
		return 0;
	}

	/* enable CDP for all ports */
	if (tegra->cdp_enabled) {
		for (j = 0; j < tegra->soc->num_typed_phys[USB2_PHY]; j++) {
			set_cdp_enable(tegra, j, true);

			if (!tegra->typed_phys[USB2_PHY][j])
				continue;
			/* skip vbus on for OTG port when it isn't host role */
			if (is_host_mode_phy(tegra, USB2_PHY, j)) {
				int port = j;

				if (tegra->soc->is_xhci_vf)
					port = tegra->port_to_phy[USB2_PHY][j];

				tegra_xusb_padctl_vbus_power_on(
					tegra->padctl, port);
			}
		}
	}

	ret = tegra_xhci_exit_elpg(tegra, false);
	if (ret < 0) {
		mutex_unlock(&tegra->lock);
		return ret;
	}

	tegra->suspended = false;
	mutex_unlock(&tegra->lock);

	tegra_xhci_update_otg_role(tegra, true);

	pm_runtime_mark_last_busy(tegra->dev);
	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	return 0;
}

static int tegra_xhci_resume_noirq(struct device *dev)
{
	struct tegra_xusb *tegra = dev_get_drvdata(dev);
	struct xhci_hcd *xhci;

	if (!tegra->fw_loaded && !tegra->soc->is_xhci_vf)
		return 0;

	xhci = hcd_to_xhci(tegra->hcd);

	if (xhci->recovery_in_progress == true)
		return 0;
	/*
	 * when CDP is enabled, VBUS will be off in SC7 and re-enabled in SC7
	 * resume. We don't have to resume earlier in noirq callback here
	 * because device will disconnect and re-connected in resume. Also,
	 * turning VBUS on in resume_noirq callback is not working if the
	 * gpio is in GPIO expander controlled through I2C bus.
	 */
	if (tegra->cdp_enabled)
		return 0;

	return tegra_xhci_resume_common(dev);
}

static int tegra_xhci_resume(struct device *dev)
{
	struct tegra_xusb *tegra = dev_get_drvdata(dev);
	struct xhci_hcd *xhci;
	int ret;

	if (!tegra->fw_loaded && !tegra->soc->is_xhci_vf)
		return 0;

	xhci = hcd_to_xhci(tegra->hcd);

	if (xhci->recovery_in_progress == true)
		return 0;

	ret = tegra_xhci_resume_common(dev);

	if (!tegra->soc->is_xhci_vf && device_may_wakeup(dev)) {
		if (disable_irq_wake(tegra->padctl_irq))
			dev_err(dev,
			"failed to disable padctl wakes\n");
	}
	return ret;
}
#endif /* IS_ENABLED(CONFIG_PM_SLEEP) */

#if IS_ENABLED(CONFIG_PM)
static int tegra_xhci_runtime_suspend(struct device *dev)
{
	struct tegra_xusb *tegra = dev_get_drvdata(dev);
	struct xhci_hcd *xhci;
	int ret;

	if ((!tegra->fw_loaded && !tegra->soc->is_xhci_vf) ||
		tegra->soc->disable_elpg)
		return 0;

	xhci = hcd_to_xhci(tegra->hcd);

	if (xhci->recovery_in_progress == true)
		return 0;

	mutex_lock(&tegra->lock);
	ret = tegra_xhci_enter_elpg(tegra, true);
	mutex_unlock(&tegra->lock);

	return ret;
}

static int tegra_xhci_runtime_resume(struct device *dev)
{
	struct tegra_xusb *tegra = dev_get_drvdata(dev);
	struct xhci_hcd *xhci;
	int ret;

	if ((!tegra->fw_loaded && !tegra->soc->is_xhci_vf) ||
		tegra->soc->disable_elpg)
		return 0;

	xhci = hcd_to_xhci(tegra->hcd);

	if (xhci->recovery_in_progress == true)
		return 0;

	mutex_lock(&tegra->lock);
	ret = tegra_xhci_exit_elpg(tegra, true);
	mutex_unlock(&tegra->lock);

	return ret;
}
#endif /* IS_ENABLED(CONFIG_PM) */

static const struct dev_pm_ops tegra_xusb_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(tegra_xusb_suspend, tegra_xhci_resume)
	SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(NULL, tegra_xhci_resume_noirq)
	SET_RUNTIME_PM_OPS(tegra_xhci_runtime_suspend,
					tegra_xhci_runtime_resume, NULL)
};

static const char * const tegra124_supply_names[] = {
	"avddio-pex",
	"dvddio-pex",
	"avdd-usb",
	"avdd-pll-utmip",
	"avdd-pll-erefe",
	"avdd-usb-ss-pll",
	"hvdd-usb-ss",
	"hvdd-usb-ss-pll-e",
};

static const struct tegra_xusb_soc tegra124_soc = {
	.device_id = XHCI_DEVICE_ID_T124,
	.firmware = "nvidia/tegra124/xusb.bin",
	.supply_names = tegra124_supply_names,
	.num_supplies = ARRAY_SIZE(tegra124_supply_names),

	.num_typed_phys[USB3_PHY] = 2,
	.num_typed_phys[USB2_PHY] = 3,
	.num_typed_phys[HSIC_PHY] = 2,

	.ports = {
		.usb2 = { .offset = 4, .count = 4, },
		.hsic = { .offset = 6, .count = 2, },
		.usb3 = { .offset = 0, .count = 2, },
	},

	.cfg_4_addr_shift = XUSB_BASE_ADDR_SHIFT,
	.cfg_4_addr_mask = XUSB_BASE_ADDR_MASK,
	.cfg_aru_mbox_cmd = XUSB_CFG_ARU_MBOX_CMD,
	.cfg_aru_mbox_data_in = XUSB_CFG_ARU_MBOX_DATA_IN,
	.cfg_aru_mbox_data_out = XUSB_CFG_ARU_MBOX_DATA_OUT,
	.cfg_aru_mbox_owner = XUSB_CFG_ARU_MBOX_OWNER,

	.scale_ss_clock = true,
	.has_ipfs = true,
	.ss_lfps_detector_war = false,
	.handle_oc = false,
	.disable_hsic_wake = false,
	.disable_elpg = false,
	.otg_set_port_power = true,
};
MODULE_FIRMWARE("nvidia/tegra124/xusb.bin");

static const char * const tegra210_supply_names[] = {
	"hvdd_usb",
	"avdd_pll_utmip",
	"vddio_hsic",
	"avddio_usb",
	"dvdd_sata",
	"avddio_pll_uerefe",
};

static const struct tegra_xusb_soc tegra210_soc = {
	.device_id = XHCI_DEVICE_ID_T210,
	.firmware = "tegra21x_xusb_firmware",
	.supply_names = tegra210_supply_names,
	.num_supplies = ARRAY_SIZE(tegra210_supply_names),

	.num_typed_phys[USB3_PHY] = 4,
	.num_typed_phys[USB2_PHY] = 4,
	.num_typed_phys[HSIC_PHY] = 1,

	.ports = {
		.usb2 = { .offset = 4, .count = 4, },
		.hsic = { .offset = 8, .count = 1, },
		.usb3 = { .offset = 0, .count = 4, },
	},

	.cfg_4_addr_shift = XUSB_BASE_ADDR_SHIFT,
	.cfg_4_addr_mask = XUSB_BASE_ADDR_MASK,
	.cfg_aru_mbox_cmd = XUSB_CFG_ARU_MBOX_CMD,
	.cfg_aru_mbox_data_in = XUSB_CFG_ARU_MBOX_DATA_IN,
	.cfg_aru_mbox_data_out = XUSB_CFG_ARU_MBOX_DATA_OUT,
	.cfg_aru_mbox_owner = XUSB_CFG_ARU_MBOX_OWNER,

	.scale_ss_clock = false,
	.has_ipfs = true,
	.ss_lfps_detector_war = true,
	.handle_oc = false,
	.disable_hsic_wake = false,
	.disable_elpg = false,
	.otg_set_port_power = true,
};
MODULE_FIRMWARE("tegra21x_xusb_firmware");

static const char * const tegra210b01_supply_names[] = {
	"hvdd_usb",
	"avdd_pll_utmip",
	"avddio_usb",
	"avddio_pll_uerefe",
};

static const struct tegra_xusb_soc tegra210b01_soc = {
	.device_id = XHCI_DEVICE_ID_T210,
	.firmware = "tegra210b01_xusb_firmware",
	.lpm_support = false,
	.supply_names = tegra210b01_supply_names,
	.num_supplies = ARRAY_SIZE(tegra210b01_supply_names),

	.num_typed_phys[USB3_PHY] = 4,
	.num_typed_phys[USB2_PHY] = 4,
	.num_typed_phys[HSIC_PHY] = 1,

	.ports = {
		.usb2 = { .offset = 4, .count = 4, },
		.hsic = { .offset = 8, .count = 1, },
		.usb3 = { .offset = 0, .count = 4, },
	},

	.cfg_4_addr_shift = XUSB_BASE_ADDR_SHIFT,
	.cfg_4_addr_mask = XUSB_BASE_ADDR_MASK,
	.cfg_aru_mbox_cmd = XUSB_CFG_ARU_MBOX_CMD,
	.cfg_aru_mbox_data_in = XUSB_CFG_ARU_MBOX_DATA_IN,
	.cfg_aru_mbox_data_out = XUSB_CFG_ARU_MBOX_DATA_OUT,
	.cfg_aru_mbox_owner = XUSB_CFG_ARU_MBOX_OWNER,

	.scale_ss_clock = false,
	.has_ipfs = true,
	.ss_lfps_detector_war = true,
	.handle_oc = true,
	.disable_hsic_wake = true,
	.disable_elpg = false,
	.otg_set_port_power = true,
};
MODULE_FIRMWARE("tegra210b01_xusb_firmware");

static const char * const tegra186_supply_names[] = {
};

static const struct tegra_xusb_soc tegra186_soc = {
	.device_id = XHCI_DEVICE_ID_T186,
	.firmware = "tegra18x_xusb_firmware",
	.lpm_support = true,
	.supply_names = tegra186_supply_names,
	.num_supplies = ARRAY_SIZE(tegra186_supply_names),
	.num_typed_phys[USB3_PHY] = 3,
	.num_typed_phys[USB2_PHY] = 3,
	.num_typed_phys[HSIC_PHY] = 1,
	.ports = {
		.usb3 = { .offset = 0, .count = 3, },
		.usb2 = { .offset = 3, .count = 3, },
		.hsic = { .offset = 6, .count = 1, },
	},

	.cfg_4_addr_shift = XUSB_BASE_ADDR_SHIFT,
	.cfg_4_addr_mask = XUSB_BASE_ADDR_MASK,
	.cfg_aru_mbox_cmd = XUSB_CFG_ARU_MBOX_CMD,
	.cfg_aru_mbox_data_in = XUSB_CFG_ARU_MBOX_DATA_IN,
	.cfg_aru_mbox_data_out = XUSB_CFG_ARU_MBOX_DATA_OUT,
	.cfg_aru_mbox_owner = XUSB_CFG_ARU_MBOX_OWNER,

	.scale_ss_clock = false,
	.has_ipfs = false,
	.ss_lfps_detector_war = false,
	.handle_oc = true,
	.disable_hsic_wake = false,
	.disable_elpg = false,
	.otg_set_port_power = true,
};
MODULE_FIRMWARE("tegra18x_xusb_firmware");

static const char * const tegra194_supply_names[] = {
};

static const struct tegra_xusb_soc tegra194_soc = {
	.device_id = XHCI_DEVICE_ID_T194,
	.firmware = "tegra19x_xusb_firmware",
	.lpm_support = true,
	.supply_names = tegra194_supply_names,
	.num_supplies = ARRAY_SIZE(tegra194_supply_names),
	.num_typed_phys[USB3_PHY] = 4,
	.num_typed_phys[USB2_PHY] = 4,
	.num_typed_phys[HSIC_PHY] = 0,
	.ports = {
		.usb3 = { .offset = 0, .count = 4, },
		.usb2 = { .offset = 4, .count = 4, },
		.hsic = { .offset = 8, .count = 0, },
	},

	.cfg_4_addr_shift = XUSB_T194_BASE_ADDR_SHIFT,
	.cfg_4_addr_mask = XUSB_T194_BASE_ADDR_MASK,
	.cfg_aru_mbox_cmd = XUSB_CFG_ARU_T194_MBOX_CMD,
	.cfg_aru_mbox_data_in = XUSB_CFG_ARU_T194_MBOX_DATA_IN,
	.cfg_aru_mbox_data_out = XUSB_CFG_ARU_T194_MBOX_DATA_OUT,
	.cfg_aru_mbox_owner = XUSB_CFG_ARU_T194_MBOX_OWNER,

	.scale_ss_clock = false,
	.has_ipfs = false,
	.ss_lfps_detector_war = false,
	.handle_oc = true,
	.disable_hsic_wake = false,
	.disable_elpg = false,
	.otg_set_port_power = false,
};
MODULE_FIRMWARE("tegra19x_xusb_firmware");

static const struct tegra_xusb_soc tegra194_vf1_soc = {
	.device_id = XHCI_DEVICE_ID_T194,
	.lpm_support = true,
	.is_xhci_vf = true,
	.vf_id = 1,
	.supply_names = tegra194_supply_names,
	.num_supplies = ARRAY_SIZE(tegra194_supply_names),
	.num_typed_phys[USB3_PHY] = 4,
	.num_typed_phys[USB2_PHY] = 4,
	.num_typed_phys[HSIC_PHY] = 0,
	/* assign ports (1 SS and 1 HS) on FPGA to linux VM */
	.ports = {
		.usb3 = { .offset = 0, .count = 4, },
		.usb2 = { .offset = 4, .count = 4, },
		.hsic = { .offset = 8, .count = 0, },
	},

	.has_ipfs = false,
	.ss_lfps_detector_war = false,
	.handle_oc = false,
	.disable_hsic_wake = false,
	.disable_elpg = false,
	.otg_set_port_power = false,
};
MODULE_FIRMWARE("tegra19x_xusb_firmware");

static const struct tegra_xusb_soc tegra194_vf2_soc = {
	.device_id = XHCI_DEVICE_ID_T194,
	.lpm_support = true,
	.is_xhci_vf = true,
	.vf_id = 2,
	.supply_names = tegra194_supply_names,
	.num_supplies = ARRAY_SIZE(tegra194_supply_names),
	.num_typed_phys[USB3_PHY] = 4,
	.num_typed_phys[USB2_PHY] = 4,
	.num_typed_phys[HSIC_PHY] = 0,
	/* assign ports (1 SS and 1 HS) on FPGA to linux VM */
	.ports = {
		.usb3 = { .offset = 0, .count = 4, },
		.usb2 = { .offset = 4, .count = 4, },
		.hsic = { .offset = 8, .count = 0, },
	},

	.has_ipfs = false,
	.ss_lfps_detector_war = false,
	.handle_oc = false,
	.disable_hsic_wake = false,
	.disable_elpg = false,
	.otg_set_port_power = false,
};
MODULE_FIRMWARE("tegra19x_xusb_firmware");

static const struct tegra_xusb_soc tegra194_vf3_soc = {
	.device_id = XHCI_DEVICE_ID_T194,
	.lpm_support = true,
	.is_xhci_vf = true,
	.vf_id = 3,
	.supply_names = tegra194_supply_names,
	.num_supplies = ARRAY_SIZE(tegra194_supply_names),
	.num_typed_phys[USB3_PHY] = 4,
	.num_typed_phys[USB2_PHY] = 4,
	.num_typed_phys[HSIC_PHY] = 0,
	/* assign ports (1 SS and 1 HS) on FPGA to linux VM */
	.ports = {
		.usb3 = { .offset = 0, .count = 4, },
		.usb2 = { .offset = 4, .count = 4, },
		.hsic = { .offset = 8, .count = 0, },
	},

	.has_ipfs = false,
	.ss_lfps_detector_war = false,
	.handle_oc = false,
	.disable_hsic_wake = false,
	.disable_elpg = false,
	.otg_set_port_power = false,
};
MODULE_FIRMWARE("tegra19x_xusb_firmware");

static const struct tegra_xusb_soc tegra194_vf4_soc = {
	.device_id = XHCI_DEVICE_ID_T194,
	.lpm_support = true,
	.is_xhci_vf = true,
	.vf_id = 4,
	.supply_names = tegra194_supply_names,
	.num_supplies = ARRAY_SIZE(tegra194_supply_names),
	.num_typed_phys[USB3_PHY] = 4,
	.num_typed_phys[USB2_PHY] = 4,
	.num_typed_phys[HSIC_PHY] = 0,
	/* assign ports (1 SS and 1 HS) on FPGA to linux VM */
	.ports = {
		.usb3 = { .offset = 0, .count = 4, },
		.usb2 = { .offset = 4, .count = 4, },
		.hsic = { .offset = 8, .count = 0, },
	},

	.has_ipfs = false,
	.ss_lfps_detector_war = false,
	.handle_oc = false,
	.disable_hsic_wake = false,
	.disable_elpg = false,
	.otg_set_port_power = false,
};
MODULE_FIRMWARE("tegra19x_xusb_firmware");

static const struct of_device_id tegra_xusb_of_match[] = {
	{ .compatible = "nvidia,tegra124-xusb", .data = &tegra124_soc },
	{ .compatible = "nvidia,tegra210-xhci", .data = &tegra210_soc },
	{ .compatible = "nvidia,tegra210b01-xhci", .data = &tegra210b01_soc },
	{ .compatible = "nvidia,tegra186-xhci", .data = &tegra186_soc },
	{ .compatible = "nvidia,tegra194-xhci", .data = &tegra194_soc },
	{ .compatible = "nvidia,tegra194-xhci-vf1", .data = &tegra194_vf1_soc },
	{ .compatible = "nvidia,tegra194-xhci-vf2", .data = &tegra194_vf2_soc },
	{ .compatible = "nvidia,tegra194-xhci-vf3", .data = &tegra194_vf3_soc },
	{ .compatible = "nvidia,tegra194-xhci-vf4", .data = &tegra194_vf4_soc },
	{ },
};
MODULE_DEVICE_TABLE(of, tegra_xusb_of_match);

static struct platform_driver tegra_xusb_driver = {
	.probe = tegra_xusb_probe,
	.remove = tegra_xusb_remove,
	.shutdown = tegra_xusb_shutdown,
	.driver = {
		.name = "tegra-xusb",
		.pm = &tegra_xusb_pm_ops,
		.of_match_table = tegra_xusb_of_match,
	},
};

static void tegra_xhci_quirks(struct device *dev, struct xhci_hcd *xhci)
{
	struct tegra_xusb *tegra = dev_get_drvdata(dev);

	xhci->quirks |= XHCI_PLAT | XHCI_SPURIOUS_WAKEUP;
	if (tegra && tegra->soc->lpm_support)
		xhci->quirks |= XHCI_LPM_SUPPORT;
}

static int tegra_xhci_setup(struct usb_hcd *hcd)
{
	return xhci_gen_setup(hcd, tegra_xhci_quirks);
}

static const struct xhci_driver_overrides tegra_xhci_overrides __initconst = {
	.extra_priv_size = sizeof(struct xhci_hcd),
	.reset = tegra_xhci_setup,
};

static void tegra_xhci_downgrade_check_to_enable(struct usb_hcd *hcd,
				    struct usb_device *udev)
{
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	int to_downgrade = 0;
	u32 portsc;
	int i;
	struct usb_downgraded_port *port_ptr;
	char *buf;
	int udev_portnum;
	unsigned long flags;

	/* If connected to USB3.0 root hub */
	if (xhci->shared_hcd->self.root_hub == udev->parent) {
		for (i = 0; i < downgraded_count; i++) {
			if ((le16_to_cpu(udev->descriptor.idVendor) ==
			    (downgraded_usb3[i] >> 16)) &&
			    (le16_to_cpu(udev->descriptor.idProduct) ==
			    (downgraded_usb3[i] & 0xFFFF))) {
				to_downgrade = 1;
				break;
			}
		}
		if (udev->quirks & USB_QUIRK_DOWNGRADE_USB3)
			to_downgrade = 1;
	}

	if (to_downgrade) {
		for (i = 0; i < DEGRADED_PORT_COUNT; i++) {
			if (!tegra->degraded_port[i].id_vendor)
				continue;
			/* If degraded already */
			if (udev->portnum == tegra->degraded_port[i].portnum)
				return;
		}

		for (i = 0; i < DEGRADED_PORT_COUNT; i++)
			if (tegra->degraded_port[i].id_vendor == 0)
				break;

		if (i < DEGRADED_PORT_COUNT) {
			dev_info(&udev->dev,
				"Downgrade idVendor=%04x idProduct=%04x to USB2.0\n",
			le16_to_cpu(udev->descriptor.idVendor),
			le16_to_cpu(udev->descriptor.idProduct));

			port_ptr = &tegra->degraded_port[i];

			/* Save information to be used by disconnect */
			port_ptr->portnum = udev->portnum;
			port_ptr->id_vendor = udev->descriptor.idVendor;
			port_ptr->id_product = udev->descriptor.idProduct;
			buf = usb_cache_string(udev,
				udev->descriptor.iSerialNumber);
			if (buf) {
				strncpy(port_ptr->serial, buf, 30);
				port_ptr->serial[30] = 0;
				kfree(buf);
			} else {
				port_ptr->serial[0] = 0;
			}
			INIT_LIST_HEAD(&port_ptr->downgraded_list);

			pm_runtime_get_sync(hcd->self.controller);
			mutex_lock(&tegra->lock);

			/* To disconnect gracefully */
			spin_lock_irqsave(&xhci->lock, flags);
			portsc = readl(xhci->usb3_ports[udev->portnum - 1]);
			portsc |= PORT_PE;
			writel(portsc, xhci->usb3_ports[udev->portnum - 1]);

			/* save it, udev will disappear if disconnect */
			udev_portnum = udev->portnum;

			spin_unlock_irqrestore(&xhci->lock, flags);
			usleep_range(10000, 12000);
			spin_lock_irqsave(&xhci->lock, flags);

			list_add_tail(&port_ptr->downgraded_list,
				&hub_downgraded_list);
			portsc = readl(xhci->usb3_ports[udev_portnum - 1]);
			portsc &= ~(PORT_PLS_MASK | PORT_PE);
			portsc |= (PORT_POWER | XDEV_RXDETECT |
				PORT_LINK_STROBE);
			writel(portsc, xhci->usb3_ports[udev_portnum - 1]);

			spin_unlock_irqrestore(&xhci->lock, flags);
			usleep_range(1000, 2000);
			spin_lock_irqsave(&xhci->lock, flags);

			/* Port Power off for downgraded USB3.0 port */
			portsc = readl(xhci->usb3_ports[udev_portnum - 1]);
			portsc &= ~(PORT_POWER | PORT_PE | PORT_CSC);
			writel(portsc, xhci->usb3_ports[udev_portnum - 1]);

			spin_unlock_irqrestore(&xhci->lock, flags);
			/*
			 * 10+360 ms, USB3.0 power off and dev polling timeout
			 * for USB2.0 pull-up to be applied
			 */
			msleep(370);
			mutex_unlock(&tegra->lock);
			pm_runtime_put(hcd->self.controller);
		}
	}
}

static int tegra_xhci_update_device(struct usb_hcd *hcd,
				    struct usb_device *udev)
{
	const struct usb_device_id *id;
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);

	for (id = disable_usb_persist_quirk_list; id->match_flags; id++) {
		if (usb_match_device(udev, id) && usb_match_speed(udev, id)) {
			udev->persist_enabled = 0;
			break;
		}
	}
	if (tegra->downgrade_enabled == 1)
		tegra_xhci_downgrade_check_to_enable(hcd, udev);

	return xhci_update_device(hcd, udev);
}

static int tegra_xhci_add_endpoint(struct usb_hcd *hcd, struct usb_device *udev,
				struct usb_host_endpoint *ep)
{
	struct usb_endpoint_descriptor *desc = &ep->desc;

	if ((udev->speed >= USB_SPEED_SUPER) &&
		((desc->bEndpointAddress & USB_ENDPOINT_DIR_MASK) ==
			USB_DIR_OUT) && usb_endpoint_xfer_bulk(desc) &&
			max_burst_war_enable) {
		if (ep->ss_ep_comp.bMaxBurst != 15) {
			dev_dbg(&udev->dev, "change ep %02x bMaxBurst (%d) to 15\n",
				ep->ss_ep_comp.bMaxBurst,
				desc->bEndpointAddress);
			ep->ss_ep_comp.bMaxBurst = 15;
		}
	}

	return xhci_add_endpoint(hcd, udev, ep);
}

static inline bool port_connected(struct tegra_xusb *tegra, unsigned int port)
{
	u32 portsc = read_portsc(tegra, port);

	return !!(portsc & PORT_CONNECT);
}

static int tegra_xhci_alloc_dev(struct usb_hcd *hcd, struct usb_device *udev)
{
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);
	int i;

	/* disable CDP for newly connected USB2.0 root hub port */
	if (tegra->cdp_enabled && usb_hcd_is_primary_hcd(hcd)) {
		for (i = 0; i < tegra->soc->num_typed_phys[USB2_PHY]; i++) {
			int port_offset =
				tegra->soc->ports.usb2.offset;

			/* find newly connected ports only */
			if (!tegra->connected_usb2_ports[i] &&
			    port_connected(tegra, port_offset + i)) {

				set_cdp_enable(tegra, i, false);
				tegra->connected_usb2_ports[i] = 1;

				/*
				 * set pad protection circuit to >= 2A
				 * CDP current range: 1.5A~5A see [BC1.2] p36
				 */
				tegra_xusb_padctl_utmi_pad_set_protection_level(
					tegra->padctl,
					tegra->typed_phys[USB2_PHY][i],
					3,
					TEGRA_VBUS_SOURCE);
			}
		}
	}

	return xhci_alloc_dev(hcd, udev);
}

static void tegra_xhci_free_dev(struct usb_hcd *hcd, struct usb_device *udev)
{
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);
	u8 port = udev->portnum - 1;
	bool is_roothub_port;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);

	if (udev == NULL)
		return;

	if (xhci == NULL) {
		dev_info(&udev->dev, "xhci is NULL");
		return;
	}

	/* If disconnected from USB2.0 root hub */
	if (xhci->main_hcd->self.root_hub == udev->parent) {
		u32 portsc = readl(xhci->usb2_ports[udev->portnum - 1]);

		if (!(portsc & PORT_CONNECT))
			tegra_xhci_downgrade_check_to_disable(hcd, udev, true);
	}

	xhci_free_dev(hcd, udev);

	/* make sure CDP is enabled for for USB2.0 root hub ports */
	is_roothub_port = udev->parent == udev->bus->root_hub;
	if (is_roothub_port && tegra->connected_usb2_ports[port] &&
			tegra->cdp_enabled && usb_hcd_is_primary_hcd(hcd)) {
		/* we have to make sure CDP is turned on before VBUS on */
		set_cdp_enable(tegra, port, true);
		tegra->connected_usb2_ports[port] = 0;
		tegra_xusb_padctl_utmi_pad_set_protection_level(
			tegra->padctl, tegra->typed_phys[USB2_PHY][port], -1,
			TEGRA_VBUS_SOURCE);
	}
}

static int tegra_xhci_urb_enqueue(struct usb_hcd *hcd, struct urb *urb,
						gfp_t mem_flags)
{
	int xfertype;
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);

	xfertype = usb_endpoint_type(&urb->ep->desc);
	switch (xfertype) {
	case USB_ENDPOINT_XFER_ISOC:
	case USB_ENDPOINT_XFER_BULK:
		if (!tegra->cpu_boost_enabled)
			break;
		if (urb->transfer_buffer_length >= tegra->boost_cpu_trigger) {
			/* break, if last boost was done within 1 sec back,
			 * because previous boost lasts for XHCI_BOOST_TIMEOUT
			 * i.e 2 sec and no need to schedule work for every
			 * transaction.
			 */
			if (time_is_after_jiffies(tegra->cpufreq_last_boosted +
				(msecs_to_jiffies(XHCI_BOOST_TIMEOUT/2))))
				break;
			schedule_work(&tegra->boost_cpufreq_work);
		}
		break;
	case USB_ENDPOINT_XFER_INT:
	case USB_ENDPOINT_XFER_CONTROL:
	default:
		/* Do nothing special here */
		break;
	}
	return xhci_urb_enqueue(hcd, urb, mem_flags);
}

static int tegra_xhci_hub_control(struct usb_hcd *hcd, u16 type_req,
		u16 value, u16 index, char *buf, u16 length)

{
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	struct xhci_bus_state *bus_state = &xhci->bus_state[hcd_index(hcd)];
	int port = (index & 0xff) - 1;
	u32 status;
	unsigned long timeout;
	int ret, wait;

	if (bus_state->resuming_ports && hcd->speed == HCD_USB2) {
		__le32 __iomem **port_array;
		int max_ports;
		u32 portsc;
		int i;

		max_ports = xhci->num_usb2_ports;
		port_array = xhci->usb2_ports;

		for (i = 0; i < max_ports; i++) {
			if (!test_bit(i, &bus_state->resuming_ports))
				continue;

			portsc = readl(port_array[i]);

			if ((i < tegra->soc->num_typed_phys[USB2_PHY])
				&& ((portsc & PORT_PLS_MASK) == XDEV_RESUME))
				tegra_phy_xusb_utmi_pad_power_on(
						tegra->typed_phys[USB2_PHY][i]);
		}
	}

	if (hcd->speed == HCD_USB2) {
		if ((type_req == ClearPortFeature) &&
			(value == USB_PORT_FEAT_SUSPEND))
			tegra_phy_xusb_utmi_pad_power_on(
					tegra->typed_phys[USB2_PHY][port]);
	}

	ret = xhci_hub_control(hcd, type_req, value, index, buf, length);

	if ((value == USB_PORT_FEAT_POWER) && !ret) {
		u32 pp_stat = (hcd->speed == HCD_USB2) ? USB_PORT_STAT_POWER :
			USB_SS_PORT_STAT_POWER;
		timeout = jiffies + HZ;
		wait = 5;
		do {
			xhci_hub_control(hcd, GetPortStatus, 0, index,
				(char *) &status, sizeof(status));
			if ((type_req == ClearPortFeature) &&
				!(status & pp_stat))
				break;
			else if ((type_req == SetPortFeature) &&
				(status & pp_stat))
				break;
			if (--wait > 0)
				usleep_range(10, 20);
			else
				msleep(200);
		} while (time_is_after_jiffies(timeout));
	}

	if ((hcd->speed == HCD_USB2) && (ret == 0)) {
		if ((type_req == SetPortFeature) &&
			(value == USB_PORT_FEAT_SUSPEND))
			/* We dont suspend the PAD while HNP role swap happens
			 * on the OTG port
			 */
			if (!((hcd->self.otg_port == (port + 1)) &&
				hcd->self.b_hnp_enable))
				tegra_phy_xusb_utmi_pad_power_down(
					  tegra->typed_phys[USB2_PHY][port]);

		if ((type_req == ClearPortFeature) &&
			(value == USB_PORT_FEAT_C_CONNECTION)) {
			struct xhci_hcd *xhci = hcd_to_xhci(hcd);
			u32 portsc = readl(xhci->usb2_ports[port]);

			if (portsc & PORT_CONNECT)
				tegra_phy_xusb_utmi_pad_power_on(
					  tegra->typed_phys[USB2_PHY][port]);
			else {
				/* We dont suspend the PAD while HNP
				 * role swap happens on the OTG port
				 */
				if (!((hcd->self.otg_port == (port + 1))
					&& hcd->self.b_hnp_enable))
					tegra_phy_xusb_utmi_pad_power_down(
					  tegra->typed_phys[USB2_PHY][port]);
			}
		}

		if ((type_req == SetPortFeature) &&
			(value == USB_PORT_FEAT_TEST)) {
			tegra_phy_xusb_utmi_pad_power_on(
				tegra->typed_phys[USB2_PHY][port]);
		}
	}

	return ret;
}

static bool device_has_isoch_ep_and_interval_one(struct usb_device *udev)
{
	struct usb_host_config *config;
	struct usb_host_interface *alt;
	struct usb_endpoint_descriptor *desc;
	int i, j;

	config = udev->actconfig;
	if (!config)
		return false;

	for (i = 0; i < config->desc.bNumInterfaces; i++) {
		alt = config->interface[i]->cur_altsetting;

		if (!alt)
			continue;

		for (j = 0; j < alt->desc.bNumEndpoints; j++) {
			desc = &alt->endpoint[j].desc;
			if (usb_endpoint_xfer_isoc(desc) &&
				desc->bInterval == 1)
				return true;
		}
	}

	return false;
}

static int tegra_xhci_enable_usb3_lpm_timeout(struct usb_hcd *hcd,
			struct usb_device *udev, enum usb3_link_state state)
{
	if ((state == USB3_LPM_U1 || state == USB3_LPM_U2) &&
		device_has_isoch_ep_and_interval_one(udev))
		return USB3_LPM_DISABLED;

	return xhci_enable_usb3_lpm_timeout(hcd, udev, state);
}

static void xhci_reinit_work(struct work_struct *work)
{
	unsigned long flags;
	struct xhci_hcd *xhci = container_of(work,
				struct xhci_hcd, tegra_xhci_reinit_work);
	struct platform_device *pdev = xhci->pdev;
	struct tegra_xusb *tegra = platform_get_drvdata(pdev);
	struct device *dev = tegra->dev;
	unsigned long target;
	bool has_active_slots = true;
	int j, ret;

	/* If the controller is in ELPG during reinit, then bring it out of
	 * elpg first before doing reinit. Otherwise we will see inconsistent
	 * behaviour. For example phy->power_count variable will be decremented
	 * twice. Once dring elpg and once during usb_remove. when phy_power_on
	 * is called during probe, the phy wont actually power on.
	 */
	mutex_lock(&tegra->lock);
	if (pm_runtime_suspended(dev)) {
		ret = tegra_xhci_exit_elpg(tegra, true);
		if (ret < 0) {
			mutex_unlock(&tegra->lock);
			dev_err(tegra->dev, "Elpg exit failed during reinit\n");
			return;
		}
	}
	mutex_unlock(&tegra->lock);


	for (j = 0; j < tegra->soc->num_typed_phys[USB2_PHY]; j++) {
		/* turn off VBUS to disconnect all devices */
		if (tegra->typed_phys[USB2_PHY][j]) {
			if (!tegra->soc->is_xhci_vf) {
				tegra_xusb_padctl_vbus_power_off(
						tegra->padctl, j);
			} else {
				tegra_xusb_padctl_vbus_power_off(
				tegra->padctl,
				tegra->port_to_phy[USB2_PHY][j]);
			}
		}
	}

	target = jiffies + msecs_to_jiffies(5000);
	/* wait until all slots have been disabled. Also waiting for 5
	 * seconds to make sure pending STOP_EP commands are completed
	 */
	while (has_active_slots && time_is_after_jiffies(target)) {
		has_active_slots = false;
		for (j = 1; j < MAX_HC_SLOTS; j++) {
			if (xhci->devs[j])
				has_active_slots = true;
		}
		msleep(300);
	}

	spin_lock_irqsave(&xhci->lock, flags);
	xhci->xhc_state |= XHCI_STATE_DYING;
	spin_unlock_irqrestore(&xhci->lock, flags);

	tegra_xusb_remove(pdev);
	usleep_range(10, 20);
	tegra_xusb_probe(pdev);

	/* probe will set recovery_in_progress to false */
}

static int tegra_xhci_hcd_reinit(struct usb_hcd *hcd)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);

	if (en_hcd_reinit && (xhci->recovery_in_progress == false)) {
		xhci->recovery_in_progress = true;
#ifdef CONFIG_USB_OTG_WAKELOCK
		/* make sure system doesn't enter suspend
		 * temporary wakelock is help for 2 seconds.
		 */
		otgwl_acquire_temp_lock();
#endif
		schedule_work(&xhci->tegra_xhci_reinit_work);
	} else {
		dev_info(tegra->dev, "hcd_reinit is disabled or in progress\n");
	}
	return 0;
}

static irqreturn_t tegra_xhci_irq(struct usb_hcd *hcd)
{
	struct tegra_xusb *tegra = hcd_to_tegra_xusb(hcd);

	if (test_bit(FW_LOG_CONTEXT_VALID, &tegra->log.flags))
		wake_up_interruptible(&tegra->log.intr_wait);

	return xhci_irq(hcd);
}

static int __init tegra_xusb_init(void)
{
	xhci_init_driver(&tegra_xhci_hc_driver, &tegra_xhci_overrides);
	tegra_xhci_hc_driver.irq = tegra_xhci_irq;
	tegra_xhci_hc_driver.update_device = tegra_xhci_update_device;
	tegra_xhci_hc_driver.add_endpoint = tegra_xhci_add_endpoint;
	tegra_xhci_hc_driver.alloc_dev = tegra_xhci_alloc_dev;
	tegra_xhci_hc_driver.free_dev = tegra_xhci_free_dev;
	tegra_xhci_hc_driver.hcd_reinit = tegra_xhci_hcd_reinit;
	tegra_xhci_hc_driver.hub_control = tegra_xhci_hub_control;
	tegra_xhci_hc_driver.enable_usb3_lpm_timeout =
		tegra_xhci_enable_usb3_lpm_timeout;
	tegra_xhci_hc_driver.urb_enqueue = tegra_xhci_urb_enqueue;

	return platform_driver_register(&tegra_xusb_driver);
}
module_init(tegra_xusb_init);

static void __exit tegra_xusb_exit(void)
{
	platform_driver_unregister(&tegra_xusb_driver);
}
module_exit(tegra_xusb_exit);

MODULE_AUTHOR("Andrew Bresticker <abrestic@chromium.org>");
MODULE_DESCRIPTION("NVIDIA Tegra XUSB xHCI host-controller driver");
MODULE_LICENSE("GPL v2");
