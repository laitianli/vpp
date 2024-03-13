#ifndef _UPAPP_FIFO_H_
#define _UPAPP_FIFO_H_
#include <stdio.h>
#include <stdlib.h>
struct udpapp_fifo {
    unsigned write;              /**< Next position to be written*/
    unsigned read;               /**< Next position to be read */
    unsigned len;                /**< Circular buffer length */
    void **volatile buffer;     /**< The buffer contains mbuf pointers */
};

#define __LOAD_ACQUIRE(src) ({                         \
        __atomic_load_n((src), __ATOMIC_ACQUIRE);           \
    })
#define __STORE_RELEASE(dst, value) do {               \
        __atomic_store_n((dst), value, __ATOMIC_RELEASE);   \
    } while(0)

static void
udpapp_fifo_init(struct udpapp_fifo *fifo, unsigned size)
{
    /* Ensure size is power of 2 */
    if (size & (size - 1)) {
        printf("[error] fifo size must be power of 2\n");
        exit(-1);
    }

    fifo->write = 0;
    fifo->read = 0;
    fifo->len = size;
    fifo->buffer = (void**)malloc(sizeof(void*) * fifo->len);
    if (!fifo->buffer) {
        printf("[Error] malloc fifo memory failed!\n");
        return ;
    }
}

static void
udpapp_fifo_uninit(struct udpapp_fifo *fifo)
{
    if (fifo->buffer)
        free(fifo->buffer);
    fifo->write = fifo->read = fifo->len = 0;
}

static inline unsigned
udpapp_fifo_put(struct udpapp_fifo *fifo, void **data, unsigned num)
{
    unsigned i = 0;
    unsigned fifo_write = __LOAD_ACQUIRE(&fifo->write);
    unsigned new_write = fifo_write;
    unsigned fifo_read = __LOAD_ACQUIRE(&fifo->read);

    for (i = 0; i < num; i++) {
        new_write = (new_write + 1) & (fifo->len - 1);

        if (new_write == fifo_read) {
            printf("[warning] [%s:%s:%d]fifo is null, put data failed!\n", __FILE__, __func__, __LINE__);
            return 0;
        }
        fifo->buffer[fifo_write] = data[i];
        fifo_write = new_write;
    }
    __STORE_RELEASE(&fifo->write, fifo_write);
    return i;
}

static inline unsigned
udpapp_fifo_get(struct udpapp_fifo *fifo, void **data, unsigned num)
{
    unsigned i = 0;
    unsigned new_read = __LOAD_ACQUIRE(&fifo->read);
    unsigned fifo_write = __LOAD_ACQUIRE(&fifo->write);

    for (i = 0; i < num; i++) {
        if (new_read == fifo_write) {
            printf("[warning][%s:%d] fifo is empty!\n", __func__, __LINE__);
            break;
        }

        data[i] = fifo->buffer[new_read];
        new_read = (new_read + 1) & (fifo->len - 1);
    }
    __STORE_RELEASE(&fifo->read, new_read);
    return i;
}

static inline unsigned int
udpapp_fifo_count(struct udpapp_fifo *fifo)
{
    unsigned fifo_write = __LOAD_ACQUIRE(&fifo->write);
    unsigned fifo_read = __LOAD_ACQUIRE(&fifo->read);
    return (fifo->len + fifo_write - fifo_read) & (fifo->len - 1);
}

static inline unsigned int
udpapp_fifo_free_count(struct udpapp_fifo *fifo)
{
    unsigned int fifo_write = __LOAD_ACQUIRE(&fifo->write);
    unsigned int fifo_read = __LOAD_ACQUIRE(&fifo->read);
    return (fifo_read - fifo_write - 1) & (fifo->len - 1);
}

#endif
