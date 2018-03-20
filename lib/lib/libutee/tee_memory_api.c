/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdlib.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_ta_interface.h>


#define TEE_LOCAL_TRACE 0
#define TEE_TAG "UTEE_MEM"

#define MALLOC_ZERO_MAGIC ((void *)0x10)

/*
 * Memory element structure; attaches hint and size value to the allocated block
 * of memory
 */
struct mem_elem {
    struct list_node mem_elem_node;
    void *buf;
    uint32_t size;
    uint32_t hint;
};

/* List of memory element structures allocated by TA instance */
static struct list_node mem_elem_list = LIST_INITIAL_VALUE(mem_elem_list);

/* Placeholders for Memory Management Functions */

static const void *tee_instance_data;

/*
 * The TEE_CheckMemoryAccessRights function causes the Implementation to examine
 * a buffer of memory specified in the parameters buffer and size and to
 * determine whether the current Trusted Application instance has the access
 * rights requested in the parameter accessFlags. If the characteristics of the
 * buffer are compatible with accessFlags, then the function returns
 * TEE_SUCCESS. Otherwise, it returns TEE_ERROR_ACCESS_DENIED. Note that the
 * buffer SHOULD NOT be accessed by the function, but the Implementation SHOULD
 * check the access rights based on the address of the buffer and internal
 * memory management information.
 *
 * The parameter accessFlags can contain one or more of the following flags:
 *  - TEE_MEMORY_ACCESS_READ : Check that the buffer is entirely readable by the
 *                             current Trusted Application instance.
 *  - TEE_MEMORY_ACCESS_WRITE : Check that the buffer is entirely writable by
                                the current Trusted Application instance.
 *  - TEE_MEMORY_ACCESS_ANY_OWNER :
 *      - If this flag is not set, then the function checks that the buffer is
 *        not shared, i.e. whether it can be safely passed in an [in] or [out]
 *        parameter.
 *      - If this flag is set, then the function does not check ownership. It
 *        returns TEE_SUCCESS if the Trusted Application instance has read or
 *        write access to the buffer, independently of whether the buffer
 *        resides in memory owned by a Client or not.
 *  - All other flags are reserved for future use and SHOULD be set to 0.
 *
 * The result of this function is valid until:
 *  - The allocated memory area containing the supplied buffer is passed to
 *    TEE_Realloc or TEE_Free.
 *  - One of the entry points of the Trusted Application returns.
 * In these two situations, the access rights of a given buffer MAY change and
 * the Trusted Application SHOULD call the function TEE_CheckMemoryAccessRights
 * again.
 *
 * When this function returns TEE_SUCCESS , and as long as this result is still
 * valid, the Implementation MUST guarantee the following properties:
 *  - For the flag TEE_MEMORY_ACCESS_READ and TEE_MEMORY_ACCESS_WRITE, the
 *    Implementation MUST guarantee that subsequent read or write accesses by
 *    the Trusted Application wherever in the buffer will succeed and will not
      panic.
 *  - When the flag TEE_MEMORY_ACCESS_ANY_OWNER is not set, the Implementation
 *    MUST guarantee that the memory buffer is owned either by the Trusted
 *    Application instance or by a more trusted component, and cannot be
 *    controlled, modified, or observed by a less trusted component, such as the
 *    Client of the Trusted Application. This means that the Trusted Application
 *    can assume the following guarantees:
 *      - Read-after-read consistency: If the Trusted Application performs two
 *        successive read accesses to the buffer at the same address and if,
 *        between the two read accesses, it performs no write, either directly
 *        or indirectly through the API to that address, then the two reads MUST
 *        return the same result.
 *      - Read-after-write consistency: If the Trusted Application writes some
 *        data in the buffer and subsequently reads the same address and if it
 *        performs no write, either directly or indirectly through the API to
 *        that address in between, the read MUST return the data.
 *      - Non-observability: If the Trusted Application writes some data in the
 *        buffer, then the data MUST NOT be observable by components less
 *        trusted than the Trusted Application itself.
 *
 * Note that when true memory sharing is implemented between Clients and the
 * Trusted Application, the Memory Reference Parameters passed to the TA entry
 * points will typically not satisfy these requirements. In this case, the
 * function TEE_CheckMemoryAccessRights MUST return TEE_ERROR_ACCESS_DENIED.
 * The code handling such buffers has to be especially careful to avoid security
 * issues brought by this lack of guarantees. For example, it can read each byte
 * in the buffer only once and refrain from writing temporary data in the buffer
 *
 * Additionally, the Implementation MUST guarantee that some types of memory
 * blocks have a minimum set of access rights:
 *  - The following blocks MUST allow read and write accesses, MUST be owned by
 *    the Trusted Application instance, and SHOULD NOT allow code execution:
 *      - All blocks returned by TEE_Malloc or TEE_Realloc
 *      - All the local and global non- const C variables
 *      - The TEE_Param structures passed to the entry points
 *        TA_OpenSessionEntryPoint and TA_InvokeCommandEntryPoint. This applies
 *        to the immediate contents of the TEE_Param structures, but not to the
 *        pointers contained in the fields of such structures, which can of
 *        course point to memory owned by the client. Note that this also means
 *        that these TEE_Param structures MUST NOT directly point to the
 *        corresponding structures in the TEE Client API (see [Client API]) or
 *        the Internal Client API (see section 4.9). The Implementation MUST
 *        perform a copy into a safe TA-owned memory buffer before passing the
 *        structures to the entry points.
 *  - The following blocks MUST allow read accesses, MUST be owned by the
 *    Trusted Application instance, and SHOULD NOT allow code execution:
 *      - All const local or global C variables
 *  - The following blocks MAY allow read accesses, MUST be owned by the
 *    Trusted Application instance, and MUST allow code execution:
 *      - The code of the Trusted Application itself
 *  - When a particular parameter passed in the structure TEE_Param to a TA
 *    entry point is a Memory Reference as specified in its parameter type,
 *    then this block, as described by the initial values of the fields buffer
 *    and size in that structure, MUST allow read and/or write accesses as
 *    specified in the parameter type. As noted above, this buffer is not
 *    required to reside in memory owned by the TA instance.
 *
 * Finally, any Implementation MUST also guarantee that the NULL pointer cannot
 * be dereferenced. If a Trusted Application attempts to read one byte at the
 * address NULL, it MUST panic. This guarantee MUST extend to a segment of
 * addresses starting at NULL , but the size of this segment is implementation-
 * dependent.
 *
 * Parameters:
 *  - buffer, size : The description of the buffer to check
 *  - accessFlags : The access flags to check
 *
 * Return Code:
 *  - TEE_SUCCESS : If the entire buffer allows the requested accesses
 *  - TEE_ERROR_ACCESS_DENIED : If at least one byte in the buffer is not
 *                              accessible with the requested accesses
 */
TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer,
                                       size_t size)
{
    TEE_Result res;

    if (size == 0)
        return TEE_SUCCESS;

    /* Check access rights against memory mapping */
    res = check_access_rights(accessFlags, buffer, size);
    if (res != TEE_SUCCESS)
        goto out;

    /*
     * Check access rights against input parameters
     * Previous legacy code was removed and will need to be restored
     */

    res = TEE_SUCCESS;
out:
    return res;
}

/*
 * The TEE_SetInstanceData and TEE_GetInstanceData functions provide an
 * alternative to writable global data (writable variables with global scope and
 * writable static variables with global or function scope). While an
 * Implementation MUST support C global variables, using these functions may be
 * sometimes more efficient, especially if only a single instance data variable
 * is required.
 * These two functions can be used to register and access an instance variable.
 * Typically this instance variable can be used to hold a pointer to a Trusted
 * Application-defined memory block containing any writable data that needs
 * instance global scope, or writable static data that needs instance function
 * scope.
 * The value of this pointer is not interpreted by the Framework, and is simply
 * passed back to other TA_ functions within this session. Note that
 * *instanceData may be set with a pointer to a buffer allocated by the Trusted
 * Application instance or with anything else, such as an integer, a handle,
 * etc. The Framework will not automatically free *instanceData when the session
 * is closed; the Trusted Application instance is responsible for freeing memory
 * if required.
 * An equivalent session context variable for managing session global and static
 * data exists for sessions (see TA_OpenSessionEntryPoint,
 * TA_InvokeCommandEntryPoint, and TA_CloseSessionEntryPoint in section 4.3).
 * This function sets the Trusted Application instance data pointer. The data
 * pointer can then be retrieved by the Trusted Application instance by calling
 * the TEE_GetInstanceData function.
 *
 * Parameters:
 *  - instanceData : A pointer to the global Trusted Application instance data.
 *                   This pointer may be NULL.
 */
void TEE_SetInstanceData(const void *instanceData)
{
    tee_instance_data = instanceData;
}

/*
 * The TEE_GetInstanceData function retrieves the instance data pointer set by
 * the Trusted Application using the TEE_SetInstanceData function.
 *
 * Return Value:
 *  - The value returned is the previously set pointer to the Trusted
 *    Application instance data, or NULL if no instance data pointer has yet
 *    been set.
 */
void *TEE_GetInstanceData(void)
{
    return (void *)tee_instance_data;
}

static struct mem_elem *get_mem_elem_from_buffer(const void *buffer)
{
    struct mem_elem *el;

    list_for_every_entry(&mem_elem_list, el, struct mem_elem, mem_elem_node)
        if (el->buf == buffer)
            return el;
    return NULL;
}

/*
 * The TEE_Malloc function allocates space for an object whose size in bytes is
 * specified in the parameter size.
 * The pointer returned is guaranteed to be aligned such that it may be assigned
 * as a pointer to any of the basic C types.
 * The parameter hint is a hint to the allocator. This parameter allows Trusted
 * Applications to refer to various pools of memory or to request special
 * characteristics for the allocated memory by using an implementation-defined
 * hint. Future versions of this specification may introduce additional standard
 * hints.
 *
 * Valid hint values:
 * --------------------------------------------------------------------------
 * | Name                 | Hint Value  | Meaning                           |
 * --------------------------------------------------------------------------
 * | TEE_MALLOC_FILL_ZERO | 0x00000000  | Guarantees that the returned block|
 * |                      |             | of memory is filled with zeroes   |
 * --------------------------------------------------------------------------
 * | Reserved             | 0x00000001- | Reserved for future versions of   |
 * |                      | 0x7FFFFFFF  | this specification.               |
 * --------------------------------------------------------------------------
 * | Implementation       | 0x80000000- | Reserved for implementation-      |
 * | defined              | 0xFFFFFFFF  | defined hints                     |
 * --------------------------------------------------------------------------
 *
 * The hint MUST be attached to the allocated block and SHOULD be used when the
 * block is reallocated with TEE_Realloc.
 * If the space cannot be allocated, given the current hint value (for example
 * because the hint value is not implemented), a NULL pointer SHALL be returned.
 *
 * Parameters:
 *  - size : The size of the buffer to be allocated.
 *  - hint : A hint to the allocator. See Table 4-17 for valid values.
 *
 * Return Value:
 *  - Upon successful completion, with size not equal to zero, the function
 *    returns a pointer to the allocated space.
 *  - If the space cannot be allocated, given the current hint value, a NULL
 *    pointer is returned.
 *  - If the size of the requested space is zero:
 *      - The value returned is undefined but guaranteed to be different from
 *        NULL. This non-NULL value ensures that the hint can be associated with
 *        the returned pointer for use by TEE_Realloc.
 *      - The Trusted Application MUST NOT access the returned pointer. The
 *        Trusted Application SHOULD panic if the memory pointed to by such a
 *        pointer is accessed for either read or write.
 */
void *TEE_Malloc(size_t size, uint32_t hint)
{
    void *buf;
    uint32_t total_size = size + sizeof(struct mem_elem);

    if (size > UINT32_MAX - sizeof(struct mem_elem))
        return NULL;

    switch (hint) {
    case TEE_MALLOC_FILL_ZERO:
    case TEE_USER_MEM_HINT_NO_FILL_ZERO:
        break;
    default:
        TEE_DBG_MSG("Undefined hint value %d\n", hint);
        return NULL;
    }

    buf = malloc((size_t)total_size);
    if (buf != NULL) {
        struct mem_elem *el = (struct mem_elem *)buf;

        el->size = size;
        el->hint = hint;
        if (!size)
            el->buf = MALLOC_ZERO_MAGIC;
        else
            el->buf = (void *)((uint8_t *)buf + sizeof(struct mem_elem));
        list_add_tail(&mem_elem_list, &el->mem_elem_node);
        buf = el->buf;

        if (hint == TEE_MALLOC_FILL_ZERO && size)
            memset(buf, 0, size);
    }

    return buf;
}

/*
 * The TEE_Realloc function changes the size of the memory object pointed to by
 * buffer to the size specified by newSize.
 * The content of the object remains unchanged up to the lesser of the new and
 * old sizes. Space in excess of the old size contains unspecified content.
 * If the new size of the memory object requires movement of the object, the
 * space for the previous instantiation of the object is deallocated. If the
 * space cannot be allocated, the original object remains allocated, and this
 * function returns a NULL pointer.
 * If buffer is NULL , TEE_Realloc is equivalent to TEE_Malloc for the specified
 * size. The associated hint applied SHALL be the default value defined in
 * TEE_Malloc .
 * It is a Programmer Error if buffer does not match a pointer previously
 * returned by TEE_Malloc or TEE_Realloc, or if the space has previously been
 * deallocated by a call to TEE_Free or TEE_Realloc.
 * If the hint initially provided when the block was allocated with TEE_Malloc
 * is 0 , then the extended space is filled with zeroes. In general, the
 * function TEE_Realloc SHOULD allocate the new memory buffer using exactly the
 * same hint as for the buffer initially allocated with TEE_Malloc. In any case,
 * it MUST NOT downgrade the security or performance characteristics of the
 * buffer.
 * Note that any pointer returned by TEE_Malloc or TEE_Realloc and not yet freed
 * or reallocated can be passed to TEE_Realloc . This includes the special
 * non- NULL pointer returned when an allocation for 0 bytes is requested.
 *
 * Parameters:
 *  - buffer : The pointer to the object to be reallocated
 *  - newSize : The new size required for the object
 *
 * Return Value:
 *  - Upon successful completion, TEE_Realloc returns a pointer to the (possibly
 *    moved) allocated space.
 *  - If there is not enough available memory, TEE_Realloc returns a NULL
 *    pointer and the original buffer is still allocated and unchanged.
 */
void *TEE_Realloc(const void *buffer, uint32_t newSize)
{
    struct mem_elem *el_old;
    uint32_t hint, old_size;
    void *ptr;
    uint32_t total_size = newSize + sizeof(struct mem_elem);
    uint32_t resize = 0;

    if (newSize > UINT32_MAX - sizeof(struct mem_elem))
        return NULL;

    if (!buffer)
        return TEE_Malloc(newSize, TEE_MALLOC_FILL_ZERO);

    el_old = get_mem_elem_from_buffer(buffer);
    if (!el_old)
        TEE_Panic(TEE_ERROR_ITEM_NOT_FOUND);

    hint = el_old->hint;
    old_size = el_old->size;

    ptr = realloc(el_old, total_size);
    if (!ptr)
        return NULL;

    if (newSize > old_size)
        resize = newSize - old_size;

    if (ptr != el_old) {
        /* Remove old list entry and add new */
        list_delete(&el_old->mem_elem_node);
        struct mem_elem *el_new = (struct mem_elem *)ptr;
        el_new->size = newSize;
        el_new->hint = hint;
        if (newSize)
            el_new->buf = (void *)((uint8_t *)el_new + sizeof(struct mem_elem));
        else
            el_new->buf = MALLOC_ZERO_MAGIC;
        list_add_tail(&mem_elem_list, &el_new->mem_elem_node);
        ptr = el_new->buf;
    } else {
        if (!newSize)
            el_old->buf = MALLOC_ZERO_MAGIC;
        else if (el_old->buf == MALLOC_ZERO_MAGIC && newSize)
            el_old->buf = (void *)((uint8_t *)el_old + sizeof(struct mem_elem));
        el_old->size = newSize;
        ptr = el_old->buf;
    }

    if (hint == TEE_MALLOC_FILL_ZERO && resize)
        memset((void *)((uint8_t *)ptr + old_size), 0, resize);

    return ptr;
}

/*
 * The TEE_Free function causes the space pointed to by buffer to be
 * deallocated; that is, made available for further allocation.
 * If buffer is a NULL pointer, TEE_Free does nothing. Otherwise, it is a
 * Programmer Error if the argument does not match a pointer previously returned
 * by the TEE_Malloc or TEE_Realloc , or if the space has been deallocated by a
 * call to TEE_Free or TEE_Realloc.
 */
void TEE_Free(void *buffer)
{
    if (!buffer)
        return;

    struct mem_elem *el = get_mem_elem_from_buffer(buffer);

    if (!el)
        TEE_Panic(TEE_ERROR_ITEM_NOT_FOUND);

    list_delete(&el->mem_elem_node);
    free(el);
}

/*
 * The TEE_MemMove function copies size bytes from the buffer pointed to by src
 * into the buffer pointed to by dest.
 * Copying takes place as if the size bytes from the buffer pointed to by src
 * are first copied into a temporary array of size bytes that does not overlap
 * the buffers pointed to by dest and src , and then the size bytes from the
 * temporary array are copied into the buffer pointed to by dest.
 *
 * Parameters:
 *  - dest : A pointer to the destination buffer
 *  - src : A pointer to the source buffer
 *  - size : The number of bytes to be copied
 */
void *TEE_MemMove(void *dest, const void *src, uint32_t size)
{
    return memmove(dest, src, size);
}

/*
 * The TEE_MemCompare function compares the first size bytes of the buffer
 * pointed to by buffer1 to the first size bytes of the buffer pointed to by
 * buffer2.
 *
 * Parameters:
 *  - buffer1 : A pointer to the first buffer
 *  - buffer2 : A pointer to the second buffer
 *  - size : The number of bytes to be compared
 *
 * Return Value:
 *  The sign of a non-zero return value is determined by the sign of the
 *  difference between the values of the first pair of bytes (both interpreted
 *  as type uint8_t) that differ in the objects being compared.
 *  - If the first byte that differs is higher in buffer1 , then return an
 *    integer greater than zero.
 *  - If the first size bytes of the two buffers are identical, then return
 *    zero.
 *  - If the first byte that differs is higher in buffer2 , then return an
 *    integer lower than zero.
 */
int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, uint32_t size)
{
    return memcmp(buffer1, buffer2, size);
}

/*
 * The TEE_MemFill function writes the byte x (converted to a uint8_t ) into the
 * first size bytes of the buffer pointed to by buffer.
 *
 * Parameters:
 *  - buffer : A pointer to the destination buffer
 *  - x : The value to be set
 *  - size : The number of bytes to be set
 */
void *TEE_MemFill(void *buff, uint32_t x, uint32_t size)
{
     return memset(buff, x, size);
}
