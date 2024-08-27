#ifndef __CIRC_BUF_H__
#define __CIRC_BUF_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define circ_buf_next_index(cur, len) ((cur) + 1 >= (len) ? 0 : (cur) + 1)
#define circ_increase_index(cur, len) ((cur) = circ_buf_next_index((cur), (len)))

#define circ_buf_prev_index(cur, len) ((cur) == 0 ? (len) - 1 : (cur) - 1)
#define circ_decrease_index(cur, len) ((cur) = circ_buf_prev_index((cur), (len)))

#define circ_buf_trans_index(cur, index, len) \
    ({ \
        ((cur) + (index) >= (len) ? \
        (cur) + (index) - (len) : \
        (cur) + (index)); \
    })

typedef struct circ_buf {
    void *buf;
    size_t buf_size;

    size_t head;
    size_t tail;
} circ_buf;

/**
 * @brief Initialize a circular buffer.
 * 
 * @param cbuf Pointer to the struct circ_buf
 * @param typename Storage type of this buffer
 * @param ptr Real storage space
 * @param size Fixed buffer size
 */
#define circ_buf_init(cbuf, typename, ptr, size) \
    do { \
        (cbuf)->buf = (ptr); \
        (cbuf)->buf_size = (size); \
        (cbuf)->head = 0; \
        (cbuf)->tail = 0; \
    } while (0)

/**
 * @brief Simply add the count of contained objects.
 * 
 * @param cbuf Pointer to the struct circ_buf
 */
#define circ_buf_addcount(cbuf) \
    do { \
        circ_increase_index((cbuf)->head, (cbuf)->buf_size); \
        if ((cbuf)->head == (cbuf)->tail) \
            circ_increase_index((cbuf)->tail, (cbuf)->buf_size); \
    } while(0)

/**
 * @brief Insert an element into a circular buffer.
 * 
 * @param cbuf Pointer to the struct circ_buf
 * @param typename Storage type of this buffer
 * @param item Pointer to the new item
 */
#define circ_buf_insert(cbuf, typename, item) \
    do { \
        memcpy((((typename *)(cbuf)->buf) + (cbuf)->head), item, sizeof(typename)); \
        circ_buf_addcount(cbuf); \
    } while(0)

/* Kernel circ_buf api.  */

/* Return count in buffer.  */
#define CIRC_CNT(head,tail,size) (((head) - (tail)) & ((size)-1))

/* Return space available, 0..size-1.  We always leave one free char
   as a completely full buffer has head == tail, which is the same as
   empty.  */
#define CIRC_SPACE(head,tail,size) CIRC_CNT((tail),((head)+1),(size))

/* Return count up to the end of the buffer.  Carefully avoid
   accessing head and tail more than once, so they can change
   underneath us without returning inconsistent results.  */
#define CIRC_CNT_TO_END(head,tail,size) \
    ({int end = (size) - (tail); \
      int n = ((head) + end) & ((size)-1); \
      n < end ? n : end;})

/* Return space available up to the end of the buffer.  */
#define CIRC_SPACE_TO_END(head,tail,size) \
    ({int end = (size) - 1 - (head); \
      int n = (end + (tail)) & ((size)-1); \
      n <= end ? n : end+1;})

/* Wrapper of them.  */
#define circ_buf_count(cbuf) CIRC_CNT((cbuf)->head, (cbuf)->tail, (cbuf)->buf_size)
#define circ_buf_space(cbuf) CIRC_SPACE((cbuf)->head, (cbuf)->tail, (cbuf)->buf_size)
#define circ_buf_count_to_end(cbuf) CIRC_CNT_TO_END((cbuf)->head, (cbuf)->tail, (cbuf)->buf_size)
#define circ_buf_space_to_end(cbuf) CIRC_SPACE_TO_END((cbuf)->head, (cbuf)->tail, (cbuf)->buf_size)

/**
 * @brief Return the pointer to beginning element for a reader.
 * 
 * @param cbuf Pointer to the struct circ_buf
 * @param typename Storage type of this buffer
 */
#define circ_buf_get_tail_entry(cbuf, typename) \
    ({ \
        ((typename *) (cbuf)->buf) + (cbuf)->tail; \
    })

/**
 * @brief Return the pointer to the next element for a writer.
 * It can be used with circ_buf_addcount(), get the entry and 
 * modify the content, then add the count, so that insert an 
 * element without using memcpy().
 * 
 * @param cbuf Pointer to the struct circ_buf
 * @param typename Storage type of this buffer
 */
#define circ_buf_get_head_entry(cbuf, typename) \
    ({ \
        ((typename *) (cbuf)->buf) + (cbuf)->head; \
    })

/**
 * @brief Get the entry of the next of an item.
 * 
 * @param cbuf Pointer to the struct circ_buf
 * @param typename Storage type of this buffer
 * @param cur_entry Entry of current item
 */
#define circ_buf_get_next_entry(cbuf, typename, cur_entry) \
    ({ \
        ((typename *) (cbuf)->buf) + \
            circ_buf_next_index(((cur_entry) - ((typename *) (cbuf)->buf)), \
                                (cbuf)->buf_size); \
    })

/**
 * @brief Return the pointer to the element with specified logic index.
 * 
 * @param cbuf Pointer to the struct circ_buf
 * @param typename Storage type of this buffer
 * @param index Logic index of the target element
 */
#define circ_buf_get_index_entry(cbuf, typename, index) \
    ({ \
        ((typename *) (cbuf)->buf) + \
            circ_buf_trans_index((cbuf)->tail, index, (cbuf)->buf_size); \
    })

/**
 * @brief Return the entry of the last element in the circ_buf.
 * 
 * @param cbuf Pointer to the struct circ_buf
 * @param typename Storage type of this buffer
 */
#define circ_buf_get_last_entry(cbuf, typename) \
    ({ \
        (circ_buf_count(cbuf) == 0) ? NULL : \
        (circ_buf_get_index_entry(cbuf, typename, circ_buf_count(cbuf) - 1)); \
    })

#define circ_buf_for_each_entry(index, pos, cbuf, typename) \
    for (index = 0, \
         pos = circ_buf_get_index_entry(cbuf, typename, index); \
         index < circ_buf_count(cbuf); \
         index++, \
         pos = circ_buf_get_index_entry(cbuf, typename, index))

#endif
