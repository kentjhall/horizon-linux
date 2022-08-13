/*
 * Copyright (c) 2014-2018, NVIDIA Corporation. All rights reserved.
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

#ifndef _TEGRA_DVFS_H_
#define _TEGRA_DVFS_H_

#include <linux/platform_device.h>
#include <soc/tegra/cvb.h>

#define MAX_DVFS_FREQS		40
#define DVFS_RAIL_STATS_TOP_BIN	200
#define DVFS_RAIL_STATS_BIN	10000
#define MAX_THERMAL_LIMITS	8
#define MAX_THERMAL_RANGES	(MAX_THERMAL_LIMITS + 1)
#define MAX_PROCESS_ID		7

enum tegra_dvfs_core_thermal_type {
	TEGRA_DVFS_CORE_THERMAL_FLOOR = 0,
	TEGRA_DVFS_CORE_THERMAL_CAP,
};

/*
 * dvfs_relationship between to rails, "from" and "to"
 * when the rail changes, it will call dvfs_rail_update on the rails
 * in the relationship_to list.
 * when determining the voltage to set a rail to, it will consider each
 * rail in the relationship_from list.
 */
struct dvfs_relationship {
	struct dvfs_rail *to;
	struct dvfs_rail *from;
	int (*solve)(struct dvfs_rail *, struct dvfs_rail *);

	struct list_head to_node; /* node in relationship_to list */
	struct list_head from_node; /* node in relationship_from list */
	bool solved_at_nominal;
};

struct cpu_pll_fv_table {
	int freq;
	int volt;
};

struct cpu_dvfs {
	int speedo_id;
	int process_id;

	int max_mv;
	int min_mv;
	struct cpu_pll_fv_table fv_table[MAX_DVFS_FREQS];

	int pll_min_millivolts; /* when PLL source is selected */
	int speedo_scale;
	int voltage_scale;
	struct cvb_table_freq_entry cvb_pll_table[MAX_DVFS_FREQS];
};

struct rail_stats {
	ktime_t time_at_mv[DVFS_RAIL_STATS_TOP_BIN + 1];
	ktime_t last_update;
	int last_index;
	bool off;
	int bin_uv;
};

struct dvfs_therm_limits {
	u32 temperature;
	u32 mv;
};

struct dvfs_rail {
	const char *reg_id;
	int min_millivolts;
	int max_millivolts;
	int nominal_millivolts;
	int override_millivolts;
	int dbg_mv_offs;

	int step;
	int step_up;
	bool jmp_to_zero;
	bool disabled;
	bool resolving_to;

	struct list_head node;  /* node in dvfs_rail_list */
	struct list_head dvfs;  /* list head of attached dvfs clocks */
	struct list_head relationships_to;
	struct list_head relationships_from;
	struct regulator *reg;
	int millivolts;
	int new_millivolts;
	int disable_millivolts;
	int suspend_millivolts;

	bool suspended;
	bool dfll_mode;
	bool joint_rail_with_dfll;

	struct rail_alignment alignment;
	struct rail_stats stats;

	struct dvfs_therm_limits *therm_floors;
	int therm_floors_size;
	int therm_floor_idx;

	bool is_ready;
	bool in_band_pm;

	struct thermal_cooling_device *vts_cdev;
	struct device_node *vts_of_node;
	struct dvfs_therm_limits vts_floors_table[MAX_THERMAL_LIMITS];
	int vts_trips_table[MAX_THERMAL_LIMITS];
	int vts_number_of_trips;
	unsigned long therm_scale_idx;

	struct thermal_cooling_device *vmax_cdev;
	struct device_node *vmax_of_node;
	struct dvfs_therm_limits *therm_caps;
	int therm_caps_size;
	int therm_cap_idx;
	bool therm_cap_warned;

	const char *nvver;
};

enum dfll_range {
	DFLL_RANGE_NONE = 0,
	DFLL_RANGE_ALL_RATES,
	DFLL_RANGE_HIGH_RATES,
};

struct dvfs {
	const char *clk_name;
	struct clk *clk;
	int speedo_id;
	int process_id;

	int freqs_mult;
	unsigned long freqs[MAX_DVFS_FREQS];
	unsigned long *alt_freqs;
	const int *millivolts;
	const int *peak_millivolts;
	const int *dfll_millivolts;
	struct dvfs_rail *dvfs_rail;
	bool auto_dvfs;

	int max_millivolts;
	int num_freqs;

	enum dfll_range	range;
	unsigned long use_dfll_rate_min;

	int cur_millivolts;
	unsigned long cur_rate;
	struct list_head node;
	struct list_head reg_node;
	bool use_alt_freqs;
	bool therm_dvfs;
	bool na_dvfs;

	/* Maximum rate safe at minimum voltage across all thermal ranges */
	unsigned long fmax_at_vmin_safe_t;
	long dbg_hz_offs;
};

struct cvb_dvfs_table {
	unsigned long freq;

	/* Coeffs for voltage calculation, when dfll clock source is selected */
	struct cvb_coefficients cvb_dfll_param;

	/* Coeffs for voltage calculation, when pll clock source is selected */
	struct cvb_coefficients cvb_pll_param;
};

struct cvb_dvfs {
	int speedo_id;
	int process_id;

	/* tuning parameters for pll clock */
	int pll_min_millivolts;

	/* dvfs Max voltage */
	int max_mv;

	/* dvfs Max frequency */
	unsigned long max_freq;
	int freqs_mult;

	/* scaling values for voltage calculation */
	int speedo_scale;
	int voltage_scale;
	int thermal_scale;

	struct cvb_dvfs_table cvb_vmin;

	/* CVB table for various frequencies */
	struct cvb_dvfs_table cvb_table[MAX_DVFS_FREQS];

	const char *cvb_version;
};

struct dvb_dvfs_table {
	unsigned long freq;
	int mvolts[MAX_PROCESS_ID + 1];
};

struct dvb_dvfs {
	int speedo_id;
	int freqs_mult;
	struct dvb_dvfs_table dvb_table[MAX_DVFS_FREQS];
};

static inline bool tegra_dvfs_rail_is_dfll_mode(struct dvfs_rail *rail)
{
	return rail ? rail->dfll_mode : false;
}

static inline bool tegra_dvfs_is_dfll_range_entry(struct dvfs *d,
						  unsigned long rate)
{
	return  d->cur_rate && d->dvfs_rail && (!d->dvfs_rail->dfll_mode) &&
		(d->range == DFLL_RANGE_HIGH_RATES) &&
		(rate >= d->use_dfll_rate_min) &&
		(d->cur_rate < d->use_dfll_rate_min);
}

static inline bool tegra_dvfs_is_dfll_scale(struct dvfs *d, unsigned long rate)
{
	return tegra_dvfs_rail_is_dfll_mode(d->dvfs_rail) ||
		tegra_dvfs_is_dfll_range_entry(d, rate);
}

static inline bool dvfs_is_dfll_range(struct dvfs *d, unsigned long rate)
{
	return (d->range == DFLL_RANGE_ALL_RATES) ||
		((d->range == DFLL_RANGE_HIGH_RATES) &&
		(rate >= d->use_dfll_rate_min));
}

#ifdef CONFIG_TEGRA_DVFS
int tegra_dvfs_dfll_mode_set(struct clk *c, unsigned long rate);
int tegra_dvfs_dfll_mode_clear(struct clk *c, unsigned long rate);
int tegra_dvfs_get_dfll_threshold(struct clk *c, unsigned long *rate);
int tegra_dvfs_set_rate(struct clk *c, unsigned long rate);
unsigned long tegra_dvfs_get_rate(struct clk *c);
int tegra_dvfs_get_freqs(struct clk *c, unsigned long **freqs, int *num_freqs);
int tegra_setup_dvfs(struct clk *c, struct dvfs *d);
int tegra_dvfs_init_rails(struct dvfs_rail *dvfs_rails[], int n);
void tegra_dvfs_init_rails_lists(struct dvfs_rail *rails[], int n);
void tegra_dvfs_add_relationships(struct dvfs_relationship *rels, int n);
void tegra_dvfs_rail_enable(struct dvfs_rail *rail);
void tegra_dvfs_rail_disable(struct dvfs_rail *rail);
int tegra_dvfs_predict_millivolts(struct clk *c, unsigned long rate);
bool tegra_dvfs_is_dfll_range(struct clk *c, unsigned long rate);
int tegra_dvfs_set_dfll_range(struct clk *c, int range);
int tegra_get_cpu_fv_table(int *num_freqs, unsigned long **freqs, int **mvs);
void tegra_dvfs_core_init_therm_limits(struct dvfs_rail *rail);
int tegra_dvfs_core_get_thermal_index(enum tegra_dvfs_core_thermal_type type);
int
tegra_dvfs_core_count_thermal_states(enum tegra_dvfs_core_thermal_type type);
int tegra_dvfs_core_update_thermal_index(enum tegra_dvfs_core_thermal_type type,
					 unsigned long new_idx);
int tegra_dvfs_core_set_thermal_cap(struct clk *cap_clk,
				    unsigned long thermal_index);
unsigned long tegra_dvfs_get_maxrate(struct clk *c);
struct dvfs_rail *tegra_dvfs_get_rail_by_name(char *name);
bool tegra_dvfs_is_rail_up(struct dvfs_rail *rail);
int tegra_dvfs_rail_power_down(struct dvfs_rail *rail);
int tegra_dvfs_rail_power_up(struct dvfs_rail *rail);
unsigned long tegra_dvfs_round_rate(struct clk *c, unsigned long rate);
int tegra_dvfs_add_alt_freqs(struct clk *c, struct dvfs *d);
int tegra_dvfs_use_alt_freqs_on_clk(struct clk *c, bool use_alt_freq);
int tegra_dvfs_predict_mv_at_hz_cur_tfloor(struct clk *c, unsigned long rate);
int tegra_dvfs_init_thermal_dvfs_voltages(int *therm_voltages,
	int *peak_voltages, int freqs_num, int ranges_num, struct dvfs *d);
long tegra_dvfs_predict_hz_at_mv_max_tfloor(struct clk *c, int mv);
int tegra_dvfs_predict_mv_at_hz_max_tfloor(struct clk *c, unsigned long rate);
unsigned long tegra_dvfs_get_fmax_at_vmin_safe_t(struct clk *c);
bool tegra_dvfs_is_rail_ready(struct dvfs_rail *rail);
#else
static inline int tegra_dvfs_dfll_mode_set(struct clk *c, unsigned long rate)
{ return -EINVAL; }
static inline int tegra_dvfs_dfll_mode_clear(struct clk *c, unsigned long rate)
{ return -EINVAL; }
static inline int tegra_dvfs_get_dfll_threshold(
		struct clk *c, unsigned long *rate)
{ return -EINVAL; }
static inline int tegra_dvfs_set_rate(struct clk *c, unsigned long rate)
{ return 0; }
static inline unsigned long tegra_dvfs_get_rate(struct clk *c)
{ return 0; }
static inline int tegra_dvfs_get_freqs(
		struct clk *c, unsigned long **freqs, int *num_freqs)
{ return -EINVAL; }
static inline int tegra_setup_dvfs(struct clk *c, struct dvfs *d)
{ return -EINVAL; }
static inline int tegra_dvfs_init_rails(struct dvfs_rail *dvfs_rails[], int n)
{ return -EINVAL; }
static inline void tegra_dvfs_init_rails_lists(struct dvfs_rail *rails[], int n)
{ return; }
static inline void tegra_dvfs_add_relationships(
		struct dvfs_relationship *rels, int n)
{ return; }
static inline void tegra_dvfs_rail_enable(struct dvfs_rail *rail)
{ return; }
static inline void tegra_dvfs_rail_disable(struct dvfs_rail *rail)
{ return; }
static inline int tegra_dvfs_predict_millivolts(
		struct clk *c, unsigned long rate)
{ return -EINVAL; }
static inline bool tegra_dvfs_is_dfll_range(struct clk *c, unsigned long rate)
{ return false; }
static inline int tegra_dvfs_set_dfll_range(struct clk *c, int range)
{ return -EINVAL; }
static inline int tegra_get_cpu_fv_table(
		int *num_freqs, unsigned long **freqs, int **mvs)
{ return -EINVAL; }
static inline void tegra_dvfs_core_init_therm_limits(struct dvfs_rail *rail)
{ return; }
static inline int tegra_dvfs_core_get_thermal_index(
					enum tegra_dvfs_core_thermal_type type)
{ return -EINVAL; }
static inline int tegra_dvfs_core_count_thermal_states(
					enum tegra_dvfs_core_thermal_type type)
{ return -EINVAL; }
static inline int tegra_dvfs_core_update_thermal_index(
					enum tegra_dvfs_core_thermal_type type,
					unsigned long new_idx)
{ return -EINVAL; }
static inline int tegra_dvfs_core_set_thermal_cap(
	struct clk *cap_clk, unsigned long thermal_index)
{ return -EINVAL; }
static inline unsigned long tegra_dvfs_get_maxrate(struct clk *c)
{ return 0; }
static inline struct dvfs_rail *tegra_dvfs_get_rail_by_name(char *name)
{ return NULL; }
static inline bool tegra_dvfs_is_rail_up(struct dvfs_rail *rail)
{ return false; }
static inline int tegra_dvfs_rail_power_down(struct dvfs_rail *rail)
{ return -EINVAL; }
static inline int tegra_dvfs_rail_power_up(struct dvfs_rail *rail)
{ return -EINVAL; }
static inline unsigned long tegra_dvfs_round_rate(struct clk *c,
						  unsigned long rate)
{ return rate; }
static inline int tegra_dvfs_add_alt_freqs(struct clk *c, struct dvfs *d)
{ return -EINVAL; }
static inline int tegra_dvfs_use_alt_freqs_on_clk(struct clk *c,
						  bool use_alt_freq)
{ return -EINVAL; }
static inline int tegra_dvfs_predict_mv_at_hz_cur_tfloor(struct clk *c,
							  unsigned long rate)
{ return -EINVAL; }
static inline int tegra_dvfs_init_thermal_dvfs_voltages(int *therm_voltages,
	int *peak_voltages, int freqs_num, int ranges_num, struct dvfs *d)
{ return -EINVAL; }
static inline long tegra_dvfs_predict_hz_at_mv_max_tfloor(struct clk *c,
							  int mv)
{ return -EINVAL; }
static inline int tegra_dvfs_predict_mv_at_hz_max_tfloor(struct clk *c,
							 unsigned long rate)
{ return -EINVAL; }
static inline unsigned long tegra_dvfs_get_fmax_at_vmin_safe_t(struct clk *c)
{ return 0; }

static inline bool tegra_dvfs_is_rail_ready(struct dvfs_rail *rail)
{ return false; }
#endif

#ifdef CONFIG_TEGRA_124_DVFS
int tegra124_init_dvfs(struct device *node);
#else
static inline int tegra124_init_dvfs(struct device *node)
{ return -EINVAL; }
#endif

#ifdef CONFIG_TEGRA_210_DVFS
int tegra210_init_dvfs(struct device *node);
int tegra210b01_init_dvfs(struct device *node);
#else
static inline int tegra210_init_dvfs(struct device *node)
{ return -EINVAL; }
static inline int tegra210b01_init_dvfs(struct device *node)
{ return -EINVAL; }
#endif

#endif
