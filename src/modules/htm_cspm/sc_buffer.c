#include <stdlib.h>
#include <string.h>
#include "sc_buffer.h"

BUFFER *buffer_new()
{
	BUFFER *buffer=malloc(sizeof(BUFFER));
	memset(buffer,0,sizeof(BUFFER));
	return (buffer);
}

void buffer_free(BUFFER *buffer)
{
	if ( buffer->m_data != NULL )
	{
		free(buffer->m_data);
	}
	free(buffer);
}

static void realloc_buffer(BUFFER *buffer,int needed)
{
	needed=(needed+0x7f) & ~0x7f;
	buffer->m_data=realloc(buffer->m_data,needed);
	buffer->m_alloc_size=needed;
}

void buffer_write(BUFFER *buffer,void *data,int len)
{
	if ( buffer->m_alloc_size < buffer->m_offset_write+len )
		realloc_buffer(buffer,buffer->m_offset_write+len);
	memcpy(buffer->m_data+buffer->m_offset_write,data,len);
	buffer->m_offset_write+=len;
}

void buffer_write_u32(BUFFER *buffer,uint32_t data)
{
	buffer_write(buffer,&data,sizeof(uint32_t));
}

void buffer_write_u16(BUFFER *buffer,uint16_t data)
{
	buffer_write(buffer,&data,sizeof(uint16_t));
}


void buffer_write_u8(BUFFER *buffer,uint8_t data)
{
	buffer_write(buffer,&data,sizeof(uint8_t));
}


void buffer_write_string(BUFFER *buffer,const char *data)
{
	buffer_write(buffer,(void *)data,strlen(data));
}

uint32_t buffer_write_size_get(BUFFER *buffer)
{
	return buffer->m_offset_write;
}
