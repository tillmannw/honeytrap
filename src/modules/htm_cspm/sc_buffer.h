#ifndef HAVE_SC_BUFFER_H
#define HAVE_SC_BUFFER_H

#include <stdint.h>

typedef struct
{
	char *m_data;
	uint32_t m_alloc_size;
//	uint32_t m_offset_read;
	uint32_t m_offset_write;
} BUFFER;

BUFFER *buffer_new();
void buffer_free(BUFFER *buffer);
//static void realloc_buffer(BUFFER *buffer,int needed);
void buffer_write(BUFFER *buffer,void *data,int len);
void buffer_write_u32(BUFFER *buffer,uint32_t data);
void buffer_write_u16(BUFFER *buffer,uint16_t data);
void buffer_write_u8(BUFFER *buffer,uint8_t data);
void buffer_write_string(BUFFER *buffer,const char *data);
uint32_t buffer_write_size_get(BUFFER *buffer);

#endif
