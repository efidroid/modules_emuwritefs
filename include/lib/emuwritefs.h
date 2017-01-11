#ifndef LIB_EMUWRITEFS_H
#define LIB_EMUWRITEFS_H

typedef void (*emuwritefs_init_cb_t)(void*);

void *emuwritefs_create_handle(void);
int emuwritefs_add_node(void* handle, const char* pathname, const char* srcfile);
int emuwritefs_main(void *handle, const char *mountpoint);

#endif // LIB_EMUWRITEFS_H
