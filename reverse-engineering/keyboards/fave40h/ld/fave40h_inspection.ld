/* SPDX-License-Identifier: GPL-2.0-or-later
 * Inspection-only geometry. Keep all linked bytes out of [0x08000000,0x08010000).
 * A conservative 64 KiB app window ends at the smallest stock flash descriptor.
 * RAM limit matches the stock software heap limit, not a physical capacity test.
 */
MEMORY {
    flash0 (rx) : org = 0x08010000, len = 64k
    flash1 (rx) : org = 0, len = 0
    flash2 (rx) : org = 0, len = 0
    flash3 (rx) : org = 0, len = 0
    flash4 (rx) : org = 0, len = 0
    flash5 (rx) : org = 0, len = 0
    flash6 (rx) : org = 0, len = 0
    flash7 (rx) : org = 0, len = 0
    ram0 (wx) : org = 0x20000000, len = 128k
    ram1 (wx) : org = 0, len = 0
    ram2 (wx) : org = 0, len = 0
    ram3 (wx) : org = 0, len = 0
    ram4 (wx) : org = 0, len = 0
    ram5 (wx) : org = 0, len = 0
    ram6 (wx) : org = 0, len = 0
    ram7 (wx) : org = 0, len = 0
}
REGION_ALIAS("VECTORS_FLASH", flash0);
REGION_ALIAS("VECTORS_FLASH_LMA", flash0);
REGION_ALIAS("XTORS_FLASH", flash0);
REGION_ALIAS("XTORS_FLASH_LMA", flash0);
REGION_ALIAS("TEXT_FLASH", flash0);
REGION_ALIAS("TEXT_FLASH_LMA", flash0);
REGION_ALIAS("RODATA_FLASH", flash0);
REGION_ALIAS("RODATA_FLASH_LMA", flash0);
REGION_ALIAS("VARIOUS_FLASH", flash0);
REGION_ALIAS("VARIOUS_FLASH_LMA", flash0);
REGION_ALIAS("RAM_INIT_FLASH_LMA", flash0);
REGION_ALIAS("MAIN_STACK_RAM", ram0);
REGION_ALIAS("PROCESS_STACK_RAM", ram0);
REGION_ALIAS("DATA_RAM", ram0);
REGION_ALIAS("DATA_RAM_LMA", flash0);
REGION_ALIAS("BSS_RAM", ram0);
REGION_ALIAS("HEAP_RAM", ram0);
INCLUDE rules.ld
