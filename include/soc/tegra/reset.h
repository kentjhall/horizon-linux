#ifndef __TEGRA_RESET_H
#define __TEGRA_RESET_H

void tegra_rst_assertv(unsigned long *id, int num);
void tegra_rst_deassertv(unsigned long *id, int num);

#endif

