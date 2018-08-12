#ifndef FDT_H
#define FDT_H

#include <inttypes.h>

/* FDT machine description */

#define FDT_MAGIC	0xd00dfeed
#define FDT_VERSION	17

struct fdt_header {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version; /* <= 17 */
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};

struct fdt_reserve_entry {
       uint64_t address;
       uint64_t size;
};

#define FDT_BEGIN_NODE	1
#define FDT_END_NODE	2
#define FDT_PROP	3
#define FDT_NOP		4
#define FDT_END		9

typedef struct {
    uint32_t *tab;
    int tab_len;
    int tab_size;
    int open_node_count;

    char *string_table;
    int string_table_len;
    int string_table_size;
} FDTState;

FDTState *fdt_init(void);
void fdt_alloc_len(FDTState *s, int len);
void fdt_put32(FDTState *s, int v);
void fdt_put_data(FDTState *s, const void *data, int len);
void fdt_begin_node(FDTState *s, const char *name);
void fdt_begin_node_num(FDTState *s, const char *name, uint64_t n);
void fdt_end_node(FDTState *s);
int fdt_get_string_offset(FDTState *s, const char *name);
void fdt_prop(FDTState *s, const char *prop_name,
                     const void *data, int data_len);
void fdt_prop_tab_u32(FDTState *s, const char *prop_name,
                             uint32_t *tab, int tab_len);
void fdt_prop_u32(FDTState *s, const char *prop_name, uint32_t val);
void fdt_prop_tab_u64_2(FDTState *s, const char *prop_name,
                               uint64_t v0, uint64_t v1);
void fdt_prop_str(FDTState *s, const char *prop_name, const char *str);
void fdt_prop_tab_str(FDTState *s, const char *prop_name, ...);
int fdt_output(FDTState *s, uint8_t *dst);
void fdt_end(FDTState *s);

#endif
