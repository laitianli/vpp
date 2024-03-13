#ifndef _UPAPP_FIFO_H_
#define _UPAPP_FIFO_H_
#include <stdio.h>
#include <stdlib.h>
struct upapp_fifo {
    unsigned write;              /**< Next position to be written*/
    unsigned read;               /**< Next position to be read */
    unsigned len;                /**< Circular buffer length */
    void **volatile buffer;     /**< The buffer contains mbuf pointers */
};

#define UPAPP_FIFO_COUNT_MAX     1024
#define upapp_fifo_SIZE          (UPAPP_FIFO_COUNT_MAX * sizeof(void *) + \
                    sizeof(struct upapp_fifo))

/**
 * @internal when c11 memory model enabled use c11 atomic memory barrier.
 * when under non c11 memory model use rte_smp_* memory barrier.
 *
 * @param src
 *   Pointer to the source data.
 * @param dst
 *   Pointer to the destination data.
 * @param value
 *   Data value.
 */
#define __LOAD_ACQUIRE(src) ({                         \
        __atomic_load_n((src), __ATOMIC_ACQUIRE);           \
    })
#define __STORE_RELEASE(dst, value) do {               \
        __atomic_store_n((dst), value, __ATOMIC_RELEASE);   \
    } while(0)

/**
 * Initializes the fifo structure
 */
static void
upapp_fifo_init(struct upapp_fifo *fifo, unsigned size)
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
upapp_fifo_uninit(struct upapp_fifo *fifo)
{
    if (fifo->buffer)
        free(fifo->buffer);
    fifo->write = fifo->read = fifo->len = 0;
}


/**
 * Adds num elements into the fifo. Return the number actually written
 */
static inline unsigned
upapp_fifo_put(struct upapp_fifo *fifo, void **data, unsigned num)
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

/**
 * Get up to num elements from the fifo. Return the number actually read
 */
static inline unsigned
upapp_fifo_get(struct upapp_fifo *fifo, void **data, unsigned num)
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

/**
 * Get the num of elements in the fifo
 */
static inline unsigned int
upapp_fifo_count(struct upapp_fifo *fifo)
{
    unsigned fifo_write = __LOAD_ACQUIRE(&fifo->write);
    unsigned fifo_read = __LOAD_ACQUIRE(&fifo->read);
    return (fifo->len + fifo_write - fifo_read) & (fifo->len - 1);
}

/**
 * Get the num of available elements in the fifo
 */
static inline unsigned int
upapp_fifo_free_count(struct upapp_fifo *fifo)
{
    unsigned int fifo_write = __LOAD_ACQUIRE(&fifo->write);
    unsigned int fifo_read = __LOAD_ACQUIRE(&fifo->read);
    return (fifo_read - fifo_write - 1) & (fifo->len - 1);
}

#endif
