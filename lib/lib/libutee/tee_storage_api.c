/*
 * Copyright (C) 2016 Imagination Technologies Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <tee_internal_api.h>

/* Generic Object Functions */

/*
 * The TEE_GetObjectInfo1 function returns the characteristics of an object. It
 * fills in the following fields in the structure TEE_ObjectInfo:
 *  - objectType : The parameter objectType passed when the object was created
 *  - keySize : The current size in bits of the object as determined by its
 *              attributes. This will always be less than or equal to
 *              maxKeySize. Set to 0 for uninitialized and data only objects.
 *  - maxKeySize: The maximum keySize which this object can represent.
 *      - For a persistent object, set to keySize
 *      - For a transient object, set to the parameter maxKeySize passed to
 *        TEE_AllocateTransientObject
 *  - objectUsage : A bit vector of the TEE_USAGE_XXX bits defined in Table 5-4.
 *  - dataSize :
 *      - For a persistent object, set to the current size of the data
 *        associated with the object
 *      - For a transient object, always set to 0
 *  - dataPosition :
 *      - For a persistent object, set to the current position in the data for
 *        this handle. Data positions for different handles on the same object
 *        may differ.
 *      - For a transient object, set to 0
 *  - handleFlags : A bit vector containing one or more of the following flags:
 *      - TEE_HANDLE_FLAG_PERSISTENT : Set for a persistent object
 *      - TEE_HANDLE_FLAG_INITIALIZED :
 *          - For a persistent object, always set
 *          - For a transient object, initially cleared, then set when the
 *            object becomes initialized
 *      - TEE_DATA_FLAG_XXX : Only for persistent objects, the flags used to
 *        open or create the object
 *
 * Parameters:
 *  - object : Handle of the object
 *  - objectInfo : Pointer to a structure filled with the object information
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_CORRUPT_OBJECT : If the persistent object is corrupt. The object
 *                               handle is closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *                                      storage area which is currently
 *                                      inaccessible.
 */
TEE_Result TEE_GetObjectInfo1(TEE_ObjectHandle object,
                              TEE_ObjectInfo *objectInfo)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_RestrictObjectUsage1 function restricts the object usage flags of an
 * object handle to contain at most the flags passed in the objectUsage
 * parameter.
 * For each bit in the parameter objectUsage :
 *  - If the bit is set to 1, the corresponding usage flag in the object is left
 *    unchanged.
 *  - If the bit is set to 0 , the corresponding usage flag in the object is
 *    cleared.
 * For example, if the usage flags of the object are set to
 * TEE_USAGE_ENCRYPT | TEE_USAGE_DECRYPT and if objectUsage is set to
 * TEE_USAGE_ENCRYPT | TEE_USAGE_EXTRACTABLE , then the only remaining usage
 * flag in the object after calling the function TEE_RestrictObjectUsage1 is
 * TEE_USAGE_ENCRYPT.
 * Note that an object usage flag can only be cleared. Once it is cleared, it
 * cannot be set to 1 again on a persistent object.
 * A transient object’s object usage flags are reset to 1 using the
 * TEE_ResetTransientObject function.
 * For a persistent object, setting the object usage MUST be an atomic
 * operation.
 *
 * Parameters:
 *  - object : Handle on an object
 *  - objectUsage : New object usage, an OR combination of one or more of the
 *                  TEE_USAGE_XXX
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_CORRUPT_OBJECT : If the persistent object is corrupt. The object
 *                               handle is closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *                                      storage area which is currently
 *                                      inaccessible.
 */
TEE_Result TEE_RestrictObjectUsage1(TEE_ObjectHandle object,
                                    uint32_t objectUsage)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_GetObjectBufferAttribute function extracts one buffer attribute from
 * an object.
 * The attribute is identified by the argument attributeID . The precise meaning
 * of this parameter depends on the container type and size and is defined in
 * section 6.11.
 * Bit [29] of the attribute identifier MUST be set to 0 , i.e. it MUST denote a
 * buffer attribute.
 * They are two kinds of object attributes, which are identified by a bit in
 * their handle value (see Table 6-17):
 *  - Public object attributes can always be extracted whatever the status of
 *    the container.
 *  - Protected attributes can be extracted only if the object’s key usage
 *    contains the TEE_USAGE_EXTRACTABLE flag.
 * See section 6.11 for a definition of all available object attributes, their
 * formats, and their level of protection.
 *
 * Parameters:
 *  - object : Handle of the object
 *  - attributeID : Identifier of the attribute to retrieve
 *  - buffer, size : Output buffer to get the content of the attribute
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_ITEM_NOT_FOUND : If the attribute is not found on this object
 *  - TEE_ERROR_SHORT_BUFFER : If buffer is NULL or too small to contain the key
 *                             part
 *  - TEE_ERROR_CORRUPT_OBJECT : If the persistent object is corrupt. The object
 *                               handle is closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *                                      storage area which is currently
 *                                      inaccessible.
 */
TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
                                        uint32_t attributeID, void *buffer,
                                        uint32_t *size)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_GetObjectValueAttribute function extracts a value attribute from an
 * object.
 * The attribute is identified by the argument attributeID . The precise meaning
 * of this parameter depends on the container type and size and is defined in
 * section 6.11.
 * Bit [29] of the attribute identifier MUST be set to 1, i.e. it MUST denote a
 * value attribute.
 * They are two kinds of object attributes, which are identified by a bit in
 * their handle value (see Table 6-17):
 *  - Public object attributes can always be extracted whatever the status of
 *    the container.
 *  - Protected attributes can be extracted only if the object’s key usage
 *    contains the TEE_USAGE_EXTRACTABLE flag.
 * See section 6.11 for a definition of all available object attributes and
 * their level of protection.
 *
 * Parameters:
 *  - object : Handle of the object
 *  - attributeID : Identifier of the attribute to retrieve
 *  - a, b : Pointers on the placeholders filled with the attribute fields a and
 *           b . Each can be NULL if the corresponding field is not of interest
 *           to the caller.
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_ITEM_NOT_FOUND : If the attribute is not found on this object
 *  - TEE_ERROR_ACCESS_DENIED : Deprecated: handled by a panic
 *  - TEE_ERROR_CORRUPT_OBJECT : If the persistent object is corrupt. The object
 *                               handle is closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *                                      storage area which is currently
 *                                      inaccessible.
 */
TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
                                       uint32_t attributeID, uint32_t *a,
                                       uint32_t *b)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_CloseObject function closes an opened object handle. The object can
 * be persistent or transient.
 * For transient objects, TEE_CloseObject is equivalent to
 * TEE_FreeTransientObject.
 * This function will operate correctly even if the object or the containing
 * storage is corrupt.
 *
 * Parameters:
 *  - object : Handle on the object to close. If set to TEE_HANDLE_NULL , does
 *             nothing.
 */
void TEE_CloseObject(TEE_ObjectHandle object)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Transient Object Functions */

/*
 * The TEE_AllocateTransientObject function allocates an uninitialized transient
 * object, i.e. a container for attributes. Transient objects are used to hold a
 * cryptographic object (key or key-pair). The object type and the maximum key
 * size MUST be specified so that all the container resources can be
 * pre-allocated.
 * As allocated, the container is uninitialized. It can be initialized by
 * subsequently importing the object material, generating an object, deriving an
 * object, or loading an object from the Trusted Storage.
 * The initial value of the key usage associated with the container is
 * 0xFFFFFFFF , which means that it contains all usage flags. You can use the
 * function TEE_RestrictObjectUsage1 to restrict the usage of the container.
 * The returned handle is used to refer to the newly-created container in all
 * subsequent functions that require an object container: key management and
 * operation functions. The handle remains valid until the container is
 * deallocated using the function TEE_FreeTransientObject.
 * As shown in Table 5-9, the object type determines the possible object size to
 * be passed to TEE_AllocateTransientObject , which is not necessarily the size
 * of the object to allocate. In particular, for key objects the size to be
 * passed is the one of the appropriate key sizes described in Table 5-9.
 * Note that a compliant Implementation MUST implement all the keys, algorithms,
 * and key sizes described in Table 5-9 except the elliptic curve cryptographic
 * types which are optional; support for other sizes or algorithms is
 * implementation-defined.
 *
 * Table 5-9: TEE_AllocateTransientObject Object Types and Key Sizes
 * ----------------------------------------------------------------------------
 * | Object Type            | Possible Key sizes                              |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_AES           | 128, 192, or 256 bits                           |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DES           | Always 64 bits including the parity bits. This  |
 * |                        | gives an effective key size of 56 bits          |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DES3          | 128 or 192 bits including the parity bits. This |
 * |                        | gives effective key sizes of 112 or 168 bits    |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_HMAC_MD5      | Between 64 and 512 bits, multiple of 8 bits     |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_HMAC_SHA1     | Between 80 and 512 bits, multiple of 8 bits     |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_HMAC_SHA224   | Between 112 and 512 bits, multiple of 8 bits    |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_HMAC_SHA256   | Between 192 and 1024 bits, multiple of 8 bits   |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_HMAC_SHA384   | Between 256 and 1024 bits, multiple of 8 bits   |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_HMAC_SHA512   | Between 256 and 1024 bits, multiple of 8 bits   |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_RSA_PUBLIC_KEY| The number of bits in the modulus. 256, 512,    |
 * |                        | 768, 1024, 1536 and 2048 bit keys MUST be       |
 * |                        | supported. Support for other key sizes including|
 * |                        | bigger key sizes is implementation-dependent.   |
 * |                        | Minimum key size is 256 bits.                   |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_RSA_KEYPAIR   | Same as for RSA public key size.                |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DSA_PUBLIC_KEY| Depends on Algorithm:                           |
 * |                        | ALG_DSA_SHA1: Between 512 and 1024 bits,        |
 * |                        | multiple of 64 bits                             |
 * |                        | ALG_DSA_SHA224: 2048 bits                       |
 * |                        | ALG_DSA_SHA256: 2048 or 3072 bits               |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DSA_KEYPAIR   | Same as for DSA public key size.                |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DH_KEYPAIR    | From 256 to 2048 bits                           |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDSA_PUBLIC_KEY| Conditional: If ECC is supported, then all the|
 * |                          | curve sizes defined in Table 6-14 MUST be     |
 * |                          | supported.                                    |
 *-----------------------------------------------------------------------------
 * | TEE_TYPE_ECDSA_KEYPAIR | Conditional: If ECC is supported, then MUST be  |
 * |                        | same value as for ECDSA public key size.        |
 * ----------------------------------------------------------------------------
 * |TEE_TYPE_ECDH_PUBLIC_KEY| Conditional: If ECC is supported, then all the  |
 * |                        | curve sizes defined in Table 6-14 MUST be       |
 * |                        | supported.                                      |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDH_KEYPAIR  | Conditional: If ECC is supported, then MUST be  |
 * |                        | same value as for ECH public key size.          |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_GENERIC_SECRET| Multiple of 8 bits, up to 4096 bits. This type  |
 * |                        | is intended for secret data that is not directly|
 * |                        | used as a key in a cryptographic operation, but |
 * |                        | participates in a key derivation.               |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DATA          | 0 – All data is in the associated data stream.  |
 * ----------------------------------------------------------------------------
 *
 * Parameters:
 *  - objectType : Type of uninitialized object container to be created
 *                 (see Table 6-13).
 *  - maxKeySize : Key Size of the object. Valid values depend on the object
 *                 type and are defined in Table 5-9 above.
 *  - object : Filled with a handle on the newly created key container
 *
 * Return Code:
 *  - TEE_SUCCESS : On success
 *  - TEE_ERROR_OUT_OF_MEMORY : If not enough resources are available to
 *                              allocate the object handle
 *  - TEE_ERROR_NOT_SUPPORTED : If the key size is not supported or the object
 *                              type is not supported.
 */
TEE_Result TEE_AllocateTransientObject(uint32_t objectType, uint32_t maxKeySize,
                                       TEE_ObjectHandle *object)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_FreeTransientObject function deallocates a transient object
 * previously allocated with TEE_AllocateTransientObject . After this function
 * has been called, the object handle is no longer valid and all resources
 * associated with the transient object MUST have been reclaimed.
 * If the object is initialized, the object attributes are cleared before the
 * object is deallocated.
 * This function does nothing if object is TEE_HANDLE_NULL.
 *
 * Parameters:
 *  - object : Handle on the object to free
 */
void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_ResetTransientObject function resets a transient object to its
 * initial state after allocation.
 * If the object is currently initialized, the function clears the object of all
 * its material. The object is then uninitialized again.
 * In any case, the function resets the key usage of the container to
 * 0xFFFFFFFFF.
 * This function does nothing if object is set to TEE_HANDLE_NULL.
 *
 * Parameters:
 *  - object : Handle on a transient object to reset
 */
void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_PopulateTransientObject function populates an uninitialized object
 * container with object attributes passed by the TA in the attrs parameter.
 * When this function is called, the object MUST be uninitialized. If the object
 * is initialized, the caller MUST first clear it using the function
 * TEE_ResetTransientObject .
 * Note that if the object type is a key-pair, then this function sets both the
 * private and public parts of the key-pair.
 * As shown in Table 5-10, the interpretation of the attrs parameter depends on
 * the object type. The values of all attributes are copied into the object so
 * that the attrs array and all the memory buffers it points to may be freed
 * after this routine returns without affecting the object.
 *
 * Table 5-10: TEE_PopulateTransientObject Supported Attributes
 * ============================================================================
 * | Object Type                | Attributes                                  |
 * ============================================================================
 * | TEE_TYPE_AES               | For all secret key objects, the             |
 * | TEE_TYPE_DES               | TEE_ATTR_SECRET_VALUE MUST be provided.     |
 * | TEE_TYPE_DES3              | For TEE_TYPE_DES and TEE_TYPE_DES3 , the    |
 * | TEE_TYPE_HMAC_MD5          | buffer associated with this attribute MUST  |
 * | TEE_TYPE_HMAC_SHA1         | include parity bits.                        |
 * | TEE_TYPE_HMAC_SHA224       |                                             |
 * | TEE_TYPE_HMAC_SHA256       |                                             |
 * | TEE_TYPE_HMAC_SHA384       |                                             |
 * | TEE_TYPE_HMAC_SHA512       |                                             |
 * | TEE_TYPE_GENERIC_SECRET    |                                             |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_RSA_PUBLIC_KEY    | The following parts MUST be provided:       |
 * |                            | TEE_ATTR_RSA_MODULUS                        |
 * |                            | TEE_ATTR_RSA_PUBLIC_EXPONENT                |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_RSA_KEYPAIR       | The following parts MUST be provided:       |
 * |                            | TEE_ATTR_RSA_MODULUS                        |
 * |                            | TEE_ATTR_RSA_PUBLIC_EXPONENT                |
 * |                            | TEE_ATTR_RSA_PRIVATE_EXPONENT               |
 * |                            | The CRT parameters are optional. If any of  |
 * |                            | these parts is provided, then all of them   |
 * |                            | MUST be provided:                           |
 * |                            | TEE_ATTR_RSA_PRIME1                         |
 * |                            | TEE_ATTR_RSA_PRIME2                         |
 * |                            | TEE_ATTR_RSA_EXPONENT1                      |
 * |                            | TEE_ATTR_RSA_EXPONENT2                      |
 * |                            | TEE_ATTR_RSA_COEFFICIENT                    |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDSA_PUBLIC_KEY  | Conditional: If ECC is supported, then the  |
 * |                            | following parts MUST be provided:           |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_X                 |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_Y                 |
 * |                            | TEE_ATTR_ECC_CURVE                          |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDSA_KEYPAIR     | Conditional: If ECC is supported, then the  |
 * |                            | following parts MUST be provided:           |
 * |                            | TEE_ATTR_ECC_PRIVATE_VALUE                  |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_X                 |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_Y                 |
 * |                            | TEE_ATTR_ECC_CURVE                          |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDH_PUBLIC_KEY   | Conditional: If ECC is supported, then the  |
 * |                            | following parts MUST be provided:           |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_X                 |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_Y                 |
 * |                            | TEE_ATTR_ECC_CURVE                          |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDH_KEYPAIR      | Conditional: If ECC is supported, then the  |
 * |                            | following parts MUST be provided:           |
 * |                            | TEE_ATTR_ECC_PRIVATE_VALUE                  |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_X                 |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_Y                 |
 * |                            | TEE_ATTR_ECC_CURVE                          |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDSA_PUBLIC_KEY  | The following parts MUST be provided:       |
 * |                            | TEE_ATTR_DSA_PRIME                          |
 * |                            | TEE_ATTR_DSA_SUBPRIME                       |
 * |                            | TEE_ATTR_DSA_BASE                           |
 * |                            | TEE_ATTR_DSA_PUBLIC_VALUE                   |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DSA_KEYPAIR       | The following parts MUST be provided:       |
 * |                            | TEE_ATTR_DSA_PRIME                          |
 * |                            | TEE_ATTR_DSA_SUBPRIME                       |
 * |                            | TEE_ATTR_DSA_BASE                           |
 * |                            | TEE_ATTR_DSA_PRIVATE_VALUE                  |
 * |                            | TEE_ATTR_DSA_PUBLIC_VALUE                   |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDH_KEYPAIR      | The following parts MUST be provided:       |
 * |                            | TEE_ATTR_DH_PRIME                           |
 * |                            | TEE_ATTR_DH_BASE                            |
 * |                            | TEE_ATTR_DH_PUBLIC_VALUE                    |
 * |                            | TEE_ATTR_DH_PRIVATE_VALUE                   |
 * |                            | Optionally, TEE_ATTR_DH_SUBPRIME may be     |
 * |                            | provided, too.                              |
 * ============================================================================
 *
 * All mandatory attributes MUST be specified, otherwise the routine will panic.
 * If attribute values are larger than the maximum size specified when the
 * object was created, the Implementation SHALL panic.
 * The Implementation can attempt to detect whether the attribute values are
 * consistent; for example, if the numbers supposed to be prime are indeed
 * prime. However, it is not required to do these checks fully and reliably. If
 * it detects invalid attributes, it MUST return the error code
 * TEE_ERROR_BAD_PARAMETERS and MUST NOT panic. If it does not detect any
 * inconsistencies, it MUST be able to later proceed with all operations
 * associated with the object without error. In this case, it is not required to
 * make sensible computations, but all computations MUST terminate and output
 * some result.
 * Only the attributes specified in Table 5-10 associated with the object’s type
 * are valid. The presence of any other attribute in the attribute list is an
 * error and will cause the routine to panic.
 *
 * Parameters:
 *  - object : Handle on an already created transient and uninitialized object
 *  - attrs, attrCount : Array of object attributes
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success. In this case, the content of the object
 *                  MUST be initialized.
 *  - TEE_ERROR_BAD_PARAMETERS : If an incorrect or inconsistent attribute value
 *                               is detected. In this case, the content of the
 *                               object MUST remain uninitialized.
 */
TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
                                       TEE_Attribute *attrs,
                                       uint32_t attrCount)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_InitRefAttribute and TEE_InitValueAttribute helper functions can be
 * used to populate a single attribute either with a reference to a buffer or
 * with integer values.
 * For example, the following code can be used to initialize a DH key
 * generation:
 *      TEE_Attribute attrs[3];
 *      TEE_InitRefAttribute(&attrs[0], TEE_ATTR_DH_PRIME, &p, len);
 *      TEE_InitRefAttribute(&attrs[1], TEE_ATTR_DH_BASE, &g, len);
 *      TEE_InitValueAttribute(&attrs[2], TEE_ATTR_DH_X_BITS, xBits, 0);
 *      TEE_GenerateKey(key, 1024, attrs, sizeof(attrs)/sizeof(TEE_Attribute));
 * Note that in the case of TEE_InitRefAttribute , only the buffer pointer is
 * copied, not the content of the buffer. This means that the attribute
 * structure maintains a pointer back to the supplied buffer. It is the
 * responsibility of the TA author to ensure that the contents of the buffer
 * maintain their value until the attributes array is no longer in use.
 *
 * Parameters:
 *  - attr : attribute structure (defined in section 5.3.1) to initialize
 *  - attributeID : Identifier of the attribute to populate, defined in section
 *                  6.11
 *  - buffer, length : Input buffer that holds the content of the attribute.
 *                     Assigned to the corresponding members of the attribute
 *                     structure defined in section 5.3.1.
 *  - a : unsigned integer value to assign to the a member of the attribute
 *        structure defined in section 5.3.1
 *  - b : unsigned integer value to assign to the b member of the attribute
 *        structure defined in section 5.3.1
 */
void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID,
                          void *buffer, uint32_t length)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_InitValueAttribute(TEE_Attribute *attr, uint32_t attributeID,
                            uint32_t a, uint32_t b)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_CopyObjectAttributes1 function populates an uninitialized object
 * handle with the attributes of another object handle; that is, it populates
 * the attributes of destObject with the attributes of srcObject.
 * It is most useful in the following situations:
 *  - To extract the public key attributes from a key-pair object
 *  - To copy the attributes from a persistent object into a transient object
 * destObject MUST refer to an uninitialized object handle and MUST therefore be
 * a transient object.
 * The source and destination objects MUST have compatible types and sizes in
 * the following sense:
 *  - The type of destObject MUST be a subtype of srcObject , i.e. one of the
 *    conditions listed in Table 5-11 MUST be true.
 *
 * Table 5-11: TEE_CopyObjectAttributes1 Parameter Types
 * ============================================================================
 * | Type of srcObject                 | Type of destObject                   |
 * ============================================================================
 * | Any                               | Equal to type of srcObject           |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_RSA_KEYPAIR              | TEE_TYPE_RSA_PUBLIC_KEY              |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DSA_KEYPAIR              | TEE_TYPE_DSA_PUBLIC_KEY              |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDSA_KEYPAIR (optional) | TEE_TYPE_ECDSA_PUBLIC_KEY (optional) |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDH_KEYPAIR (optional)  | TEE_TYPE_ECDH_PUBLIC_KEY (optional)  |
 * ============================================================================
 *
 *  - The size of srcObject MUST be less than or equal to the maximum size of
 *    destObject .
 * The effect of this function on destObject is identical to the function
 * TEE_PopulateTransientObject except that the attributes are taken from
 * srcObject instead of from parameters.
 * The object usage of destObject is set to the bitwise AND of the current
 * object usage of destObject and the object usage of srcObject.
 *
 * Parameters:
 *  - destObject : Handle on an uninitialized transient object
 *  - srcObject : Handle on an initialized object
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_CORRUPT_OBJECT : If the persistent object is corrupt. The object
 *                               handle is closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *                                      storage area which is currently
 *                                      inaccessible.
 */
TEE_Result TEE_CopyObjectAttributes1(TEE_ObjectHandle destObject,
                                     TEE_ObjectHandle srcObject)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_GenerateKey function generates a random key or a key-pair and
 * populates a transient key object with the generated key material.
 * The size of the desired key is passed in the keySize parameter and MUST be
 * less than or equal to the maximum key size specified when the transient
 * object was created. The valid values for key size are defined in Table 5-9.
 * As shown in Table 5-12, the generation algorithm can take parameters
 * depending on the object type.
 *
 * Table 5-12: TEE_GenerateKey Parameters
 * ============================================================================
 * | Object Type                | Details                                     |
 * ============================================================================
 * | TEE_TYPE_AES               | No parameter is necessary. The function     |
 * | TEE_TYPE_DES               | generates the atribute TEE_ATTR_SECRET_VALUE|
 * | TEE_TYPE_DES3              | The generated value SHALL be the full key   |
 * | TEE_TYPE_HMAC_MD5          | size.                                       |
 * | TEE_TYPE_HMAC_SHA1         |                                             |
 * | TEE_TYPE_HMAC_SHA224       |                                             |
 * | TEE_TYPE_HMAC_SHA256       |                                             |
 * | TEE_TYPE_HMAC_SHA384       |                                             |
 * | TEE_TYPE_HMAC_SHA512       |                                             |
 * | TEE_TYPE_GENERIC_SECRET    |                                             |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_RSA_KEYPAIR       | No parameter is required.                   |
 * |                            | The TEE_ATTR_RSA_PUBLIC_EXPONENT attribute  |
 * |                            | may be specified; if omitted, the default   |
 * |                            | value is 65537. Key generation SHALL follow |
 * |                            | the rules defined in [NIST SP800-56B].      |
 * |                            | The function generates and populates the    |
 * |                            | following attributes:                       |
 * |                            | TEE_ATTR_RSA_MODULUS                        |
 * |                            | TEE_ATTR_RSA_PUBLIC_EXPONENT                |
 * |                            | TEE_ATTR_RSA_PRIVATE_EXPONENT               |
 * |                            | TEE_ATTR_RSA_PRIME1                         |
 * |                            | TEE_ATTR_RSA_PRIME2                         |
 * |                            | TEE_ATTR_RSA_EXPONENT1                      |
 * |                            | TEE_ATTR_RSA_EXPONENT2                      |
 * |                            | TEE_ATTR_RSA_COEFFICIENT                    |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DSA_KEYPAIR       | The following domain parameter MUST be      |
 * |                            | passed to the function:                     |
 * |                            | TEE_ATTR_DSA_PRIME                          |
 * |                            | TEE_ATTR_DSA_SUBPRIME                       |
 * |                            | TEE_ATTR_DSA_BASE                           |
 * |                            | The function generates and populates the    |
 * |                            | following attributes:                       |
 * |                            | TEE_ATTR_DSA_PUBLIC_VALUE                   |
 * |                            | TEE_ATTR_DSA_PRIVATE_VALUE                  |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_DH_KEYPAIR        | The following domain parameters MUST be     |
 * |                            | passed to the function:                     |
 * |                            | TEE_ATTR_DH_PRIME                           |
 * |                            | TEE_ATTR_DH_BASE                            |
 * |                            | The following parameters can optionally be  |
 * |                            | passed:                                     |
 * |                            | TEE_ATTR_DH_SUBPRIME (q): If present,       |
 * |                            | constrains the private value x to be in the |
 * |                            | range [2, q-2]                              |
 * |                            | TEE_ATTR_DH_X_BITS ( l ): If present,       |
 * |                            | constrains the private value x to have l bit|
 * |                            | If neither of these optional parts is       |
 * |                            | specified, then the only constraint on x is |
 * |                            | that it is less than p-1.                   |
 * |                            | The function generates and populates the    |
 * |                            | following attributes:                       |
 * |                            | TEE_ATTR_DH_PUBLIC_VALUE                    |
 * |                            | TEE_ATTR_DH_PRIVATE_VALUE                   |
 * |                            | TEE_ATTR_DH_X_BITS (number of bits in x)    |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDSA_KEYPAIR     | The following domain parameters MUST be     |
 * |                            | passed to the function:                     |
 * |                            | TEE_ATTR_ECC_CURVE                          |
 * |                            | The function generates and populates the    |
 * |                            | following attributes:                       |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_X                 |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_Y                 |
 * |                            | TEE_ATTR_ECC_PRIVATE_VALUE                  |
 * ----------------------------------------------------------------------------
 * | TEE_TYPE_ECDH_KEYPAIR      | The following domain parameters MUST be     |
 * |                            | passed to the function:                     |
 * |                            | TEE_ATTR_ECC_CURVE                          |
 * |                            | The function generates and populates the    |
 * |                            | following attributes:                       |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_X                 |
 * |                            | TEE_ATTR_ECC_PUBLIC_VALUE_Y                 |
 * |                            | TEE_ATTR_ECC_PRIVATE_VALUE                  |
 * ============================================================================
 *
 * Once the key material has been generated, the transient object is populated
 * exactly as in the function TEE_PopulateTransientObject except that the key
 * material is randomly generated internally instead of being passed by the
 * caller.
 *
 * Parameters:
 *  - object : Handle on an uninitialized transient key to populate with the
 *    generated key
 *  - keySize : Requested key size. MUST be less than or equal to the maximum
 *    key size specified when the object container was created. MUST be a valid
 *    value as defined in Table 5-9.
 *  - params, paramCount : Parameters for the key generation. The values of all
 *    parameters are copied into the object so that the params array and all the
 *    memory buffers it points to may be freed after this routine returns
 *    without affecting the object.
 *
 * Return Code:
 *  - TEE_SUCCESS : On success
 *  - TEE_ERROR_BAD_PARAMETERS : If an incorrect or inconsistent attribute is
 *                               detected. The checks that are performed depend
 *                               on the implementation.
 */
TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
                           TEE_Attribute *params, uint32_t paramCount)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Persistent Object Functions */

/*
 * The TEE_OpenPersistentObject function opens a handle on an existing
 * persistent object. It returns a handle that can be used to access the
 * object’s attributes and data stream.
 * The storageID parameter indicates which Trusted Storage Space to access.
 * Possible values are defined in Table 5-2.
 * The flags parameter is a set of flags that controls the access rights and
 * sharing permissions with which the object handle is opened. The value of the
 * flags parameter is constructed by a bitwise-inclusive OR of flags from the
 * following list:
 *  - Access control flags:
 *      - TEE_DATA_FLAG_ACCESS_READ : The object is opened with the read access
 *        right. This allows the Trusted Application to call the function
 *        TEE_ReadObjectData.
 *      - TEE_DATA_FLAG_ACCESS_WRITE : The object is opened with the write
 *        access right. This allows the Trusted Application to call the
 *        functions TEE_WriteObjectData and TEE_TruncateObjectData.
 *      - TEE_DATA_FLAG_ACCESS_WRITE_META : The object is opened with the
 *        write-meta access right. This allows the Trusted Application to call
 *        the functions TEE_CloseAndDeletePersistentObject and
 *        TEE_RenamePersistentObject.
 *  - Sharing permission control flags:
 *      - TEE_DATA_FLAG_SHARE_READ : The caller allows another handle on the
 *        object to be created with read access.
 *      - TEE_DATA_FLAG_SHARE_WRITE : The caller allows another handle on the
 *        object to be created with write access.
 *  - Other flags are reserved for future use and SHALL be set to 0.
 * Multiple handles may be opened on the same object simultaneously, but sharing
 * MUST be explicitly allowed as described in section 5.7.3.
 * The initial data position in the data stream is set to 0.
 * Every Trusted Storage implementation is expected to return
 * TEE_ERROR_CORRUPT_OBJECT if a Trusted Application attempts to open an object
 * and the TEE determines that its contents (or those of the storage itself)
 * have been tampered with or rolled back.
 *
 * Parameters:
 *  - storageID : The storage to use. Valid values are defined in Table 5-2.
 *  - objectID, objectIDLen : The object identifier. Note that this buffer
 *    cannot reside in shared memory.
 *  - flags : The flags which determine the settings under which the object is
 *    opened.
 *  - object : A pointer to the handle, which contains the opened handle upon
 *    successful completion.
 * If this function fails for any reason, the value pointed to by object is set
 * to TEE_HANDLE_NULL.
 * When the object handle is no longer required, it MUST be closed using a call
 * to the TEE_CloseObject function.
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_ITEM_NOT_FOUND : If the storage denoted by storageID does not
 *    exist or if the object identifier cannot be found in the storage
 *  - TEE_ERROR_ACCESS_CONFLICT : If an access right conflict was detected while
 *    opening the object
 *  - TEE_ERROR_OUT_OF_MEMORY : If there is not enough memory to complete the
 *    operation
 *  - TEE_ERROR_CORRUPT_OBJECT : If the storage or object is corrupt
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_OpenPersistentObject(uint32_t storageID, void *objectID,
                                    uint32_t objectIDLen, uint32_t flags,
                                    TEE_ObjectHandle *object)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_CreatePersistentObject function creates a persistent object with
 * initial attributes and an initial data stream content, and optionally returns
 * either a handle on the created object, or TEE_HANDLE_NULL upon failure.
 * The storageID parameter indicates which Trusted Storage Space to access.
 * Possible values are defined in Table 5-2.
 * The flags parameter is a set of flags that controls the access rights,
 * sharing permissions, and object creation mechanism with which the object
 * handle is opened. The value of the flags parameter is constructed by a
 * bitwise-inclusive OR of flags from the following list:
 *  - Access control flags:
 *      - TEE_DATA_FLAG_ACCESS_READ : The object is opened with the read access
 *        right. This allows the Trusted Application to call the function
 *        TEE_ReadObjectData.
 *      - TEE_DATA_FLAG_ACCESS_WRITE : The object is opened with the write
 *        access right. This allows the Trusted Application to call the
 *        functions TEE_WriteObjectData and TEE_TruncateObjectData.
 *      - TEE_DATA_FLAG_ACCESS_WRITE_META : The object is opened with the
 *        write-meta access right. This allows the Trusted Application to call
 *        the functions TEE_CloseAndDeletePersistentObject and
 *        TEE_RenamePersistentObject.
 *  - Sharing permission control flags:
 *      - TEE_DATA_FLAG_SHARE_READ : The caller allows another handle on the
 *        object to be created with read access.
 *      - TEE_DATA_FLAG_SHARE_WRITE : The caller allows another handle on the
 *        object to be created with write access.
 *  - TEE_DATA_FLAG_OVERWRITE : As summarized in Table 5-13:
 *      - If this flag is present and the object exists, then the object is
 *        deleted and re-created as an atomic operation: that is the TA sees
 *        either the old object or the new one.
 *      - If the flag is absent and the object exists, then the function SHALL
 *        return TEE_ERROR_ACCESS_CONFLICT.
 *  - Other flags are reserved for future use and SHALL be set to 0.
 * The attributes of the newly created persistent object are taken from
 * attributes , which can be another persistent object or an initialized
 * transient object. The attributes argument can also be NULL for a pure data
 * object. The object type, size, and usage are copied from attributes. If
 * attributes is NULL, the object type SHALL be set to TEE_TYPE_DATA to create a
 * pure data object.
 * Multiple handles may be opened on the same object simultaneously, but sharing
 * MUST be explicitly allowed as described in section 5.7.3.
 * The initial data position in the data stream is set to 0.
 *
 * Table 5-13: Effect of TEE_DATA_FLAG_OVERWRITE on Behavior of
 * TEE_CreatePersistentObject:
 * ============================================================================
 * | TEE_DATA_FLAG_OVERWRITE | Object |  Object  |  Return Code               |
 * | in flags                | Exists | Created? |                            |
 * ----------------------------------------------------------------------------
 * | Absent                  | No     | Yes      | TEE_SUCCESS                |
 * ----------------------------------------------------------------------------
 * | Absent                  | Yes    | No       | TEE_ERROR_ACCESS_CONFLICT  |
 * ----------------------------------------------------------------------------
 * | Present                 | No     | Yes      | TEE_SUCCESS                |
 * ----------------------------------------------------------------------------
 * | Present                 | Yes    | Deleted  | TEE_SUCCESS                |
 * |                         |        |  and     |                            |
 * |                         |        |re-created|                            |
 * |                         |        | as an    |                            |
 * |                         |        | atomic   |                            |
 * |                         |        | operation|                            |
 * ============================================================================
 *
 * Parameters:
 *  - storageID : The storage to use. Valid values are defined in Table 5-2.
 *  - objectID, objectIDLen : The object identifier. Note that this cannot
 *    reside in shared memory.
 *  - flags : The flags which determine the settings under which the object is
 *    opened
 *  - attributes : A handle on a persistent object or an initialized transient
 *    object from which to take the persistent object attributes. Can be
 *    TEE_HANDLE_NULL if the persistent object contains no attribute; for
 *    example, if it is a pure data object.
 *  - initialData, initialDataLen : The initial data content of the persistent
 *    object
 *  - object : A pointer to the handle, which contains the opened handle upon
 *    successful completion. If this function fails for any reason, the value
 *    pointed to by object is set to TEE_HANDLE_NULL . When the object handle is
 *    no longer required, it MUST be closed using a call to the TEE_CloseObject
 *    function.
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_ITEM_NOT_FOUND : If the storage denoted by storageID does not
 *    exist
 *  - TEE_ERROR_ACCESS_CONFLICT : If an access right conflict was detected while
 *    opening the object
 *  - TEE_ERROR_OUT_OF_MEMORY : If there is not enough memory to complete the
 *    operation
 *  - TEE_ERROR_STORAGE_NO_SPACE : If insufficient space is available to create
 *    the persistent object
 *  - TEE_ERROR_CORRUPT_OBJECT : If the storage is corrupt
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_CreatePersistentObject(uint32_t storageID, void *objectID,
                                      uint32_t objectIDLen, uint32_t flags,
                                      TEE_ObjectHandle attributes,
                                      const void *initialData,
                                      uint32_t initialDataLen,
                                      TEE_ObjectHandle *object)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_CloseAndDeletePersistentObject1 function marks an object for deletion
 * and closes the object handle.
 * The object handle MUST have been opened with the write-meta access right,
 * which means access to the object is exclusive.
 * Deleting an object is atomic; once this function returns, the object is
 * definitely deleted and no more open handles for the object exist. This SHALL
 * be the case even if the object or the storage containing it have become
 * corrupted.
 * The only reason this routine can fail is if the storage area containing the
 * object becomes inaccessible (e.g. the user removes the media holding the
 * object). In this case TEE_ERROR_STORAGE_NOT_AVAILABLE SHALL be returned.
 * If object is TEE_HANDLE_NULL , the function does nothing.
 *
 * Parameters:
 *  - object : The object handle
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_CloseAndDeletePersistentObject1(TEE_ObjectHandle object)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The function TEE_RenamePersistentObject changes the identifier of an object.
 * The object handle MUST have been opened with the write-meta access right,
 * which means access to the object is exclusive. Renaming an object is an
 * atomic operation; either the object is renamed or nothing happens.
 *
 * Parameters:
 *  - object : The object handle
 *  - newObjectID, newObjectIDLen : A buffer containing the new object
 *    identifier. The identifier contains arbitrary bytes, including the zero
 *    byte. The identifier length MUST be less than or equal to
 *    TEE_OBJECT_ID_MAX_LEN and can be zero. The buffer containing the new
 *    object identifier cannot reside in shared memory.
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_ACCESS_CONFLICT : If an object with the same identifier already
 *    exists
 *  - TEE_ERROR_CORRUPT_OBJECT : If the object is corrupt. The object handle is
 *    closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object,
                                      const void *newObjectID,
                                      uint32_t newObjectIDLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Persistent Object Enumeration Functions*/

/*
 * The TEE_AllocatePersistentObjectEnumerator function allocates a handle on an
 * object enumerator.
 * Once an object enumerator handle has been allocated, it can be reused for
 * multiple enumerations.
 *
 * Parameters:
 *  - objectEnumerator : A pointer filled with the newly-allocated object
 *    enumerator handle on success. Set to TEE_HANDLE_NULL in case of error.
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_OUT_OF_MEMORY : If there is not enough memory to allocate the
 *    enumerator handle
 */
TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle
                                                  *objectEnumerator)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_FreePersistentObjectEnumerator function deallocates all resources
 * associated with an object enumerator handle. After this function is called,
 * the handle is no longer valid.
 *
 * Parameters:
 *  - objectEnumerator : The handle to close. If objectEnumerator is
 *    TEE_HANDLE_NULL , then this function does nothing.
 */
void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_ResetPersistentObjectEnumerator function resets an object enumerator
 * handle to its initial state after allocation. If an enumeration has been
 * started, it is stopped.
 * This function does nothing if objectEnumerator is TEE_HANDLE_NULL .
 *
 * Parameters:
 *  - objectEnumerator : The handle to reset
 */
void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_StartPersistentObjectEnumerator function starts the enumeration of
 * all the persistent objects in a given Trusted Storage. The object information
 * can be retrieved by calling the function TEE_GetNextPersistentObject
 * repeatedly.
 * The enumeration does not necessarily reflect a given consistent state of the
 * storage: During the enumeration, other TAs or other instances of the TA may
 * create, delete, or rename objects. It is not guaranteed that all objects will
 * be returned if objects are created or destroyed while the enumeration is in
 * progress.
 * To stop an enumeration, the TA can call the function
 * TEE_ResetPersistentObjectEnumerator , which detaches the enumerator from the
 * Trusted Storage. The TA can call the function
 * TEE_FreePersistentObjectEnumerator to completely deallocate the object
 * enumerator.
 * If this function is called on an enumerator that has already been started,
 * the enumeration is first reset then started.
 *
 * Parameters:
 *  - objectEnumerator : A valid handle on an object enumerator
 *  - storageID : The identifier of the storage in which the objects MUST be
 *    enumerated. Possible values are defined in Table 5-2.
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_ITEM_NOT_FOUND : If the storage does not exist or if there is no
 *    object in the specified storage
 *  - TEE_ERROR_CORRUPT_OBJECT : If the storage is corrupt
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle
                                                   objectEnumerator,
                                               uint32_t storageID)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_GetNextPersistentObject function gets the next object in an
 * enumeration and returns information about the object: type, size, identifier,
 * etc.
 * If there are no more objects in the enumeration or if there is no enumeration
 * started, then the function returns TEE_ERROR_ITEM_NOT_FOUND.
 * If while enumerating objects a corrupt object is detected, then its object
 * ID SHALL be returned in objectID, objectInfo shall be zeroed, and the
 * function SHALL return TEE_ERROR_CORRUPT_OBJECT.
 *
 * Parameters:
 *  - objectEnumerator : A handle on the object enumeration
 *  - objectInfo : A pointer to a TEE_ObjectInfo filled with the object
 *    information as specified in the function TEE_GetObjectInfo1 in section
 *    5.5.1. It may be NULL.
 *  - objectID : Pointer to an array able to hold at least TEE_OBJECT_ID_MAX_LEN
 *    bytes. On exit the object identifier is written to this location
 *  - objectIDLen : Filled with the size of the object identifier (from 0 to
 *    TEE_OBJECT_ID_MAX_LEN)
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_ITEM_NOT_FOUND : If there are no more elements in the object
 *    enumeration or if no enumeration is started on this handle
 *  - TEE_ERROR_CORRUPT_OBJECT : If the storage or returned object is corrupt
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
                                       TEE_ObjectInfo *objectInfo,
                                       void *objectID, uint32_t *objectIDLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Data Stream Access Functions */

/*
 * The TEE_ReadObjectData function attempts to read size bytes from the data
 * stream associated with the object object into the buffer pointed to by
 * buffer.
 * The object handle MUST have been opened with the read access right.
 * The bytes are read starting at the position in the data stream currently
 * stored in the object handle. The handle’s position is incremented by the
 * number of bytes actually read.
 * On completion TEE_ReadObjectData sets the number of bytes actually read in
 * the uint32_t pointed to by count. The value written to *count may be less
 * than size if the number of bytes until the end-of-stream is less than size.
 * It is set to 0 if the position at the start of the read operation is at or
 * beyond the end-of-stream. These are the only cases where *count may be less
 * than size.
 * No data transfer can occur past the current end of stream. If an attempt is
 * made to read past the end-of-stream, the TEE_ReadObjectData function stops
 * reading data at the end-of-stream and returns the data read up to that point.
 * This is still a success. The position indicator is then set at the
 * end-of-stream. If the position is at, or past, the end of the data when this
 * function is called, then no bytes are copied to *buffer and *count is set to
 * 0.
 *
 * Parameters:
 *  - object : The object handle
 *  - buffer : A pointer to the memory which, upon successful completion,
 *    contains the bytes read
 *  - size : The number of bytes to read
 *  - count : A pointer to the variable which upon successful completion
 *    contains the number of bytes read
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_CORRUPT_OBJECT : If the object is corrupt. The object handle is
 *    closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer,
                              uint32_t size, uint32_t *count)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_WriteObjectData function writes size bytes from the buffer pointed to
 * by buffer to the data stream associated with the open object handle object.
 * The object handle MUST have been opened with the write access permission.
 * If the current data position points before the end-of-stream, then size bytes
 * are written to the data stream, overwriting bytes starting at the current
 * data position. If the current data position points beyond the stream’s end,
 * then the data stream is first extended with zero bytes until the length
 * indicated by the data position indicator is reached, and then size bytes are
 * written to the stream. Thus, the size of the data stream can be increased as
 * a result of this operation.
 * If the operation would move the data position indicator to beyond its maximum
 * possible value, then TEE_ERROR_OVERFLOW is returned and the operation fails.
 * The data position indicator is advanced by size. The data position indicators
 * of other object handles opened on the same object are not changed.
 * Writing in a data stream is atomic; either the entire operation completes
 * successfully or no write is done.
 *
 * Parameters:
 *  - object : The object handle
 *  - buffer : The buffer containing the data to be written
 *  - size : The number of bytes to write
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_STORAGE_NO_SPACE : If insufficient storage space is available
 *  - TEE_ERROR_OVERFLOW : If the value of the data position indicator resulting
 *    from this operation would be greater than TEE_DATA_MAX_POSITION
 *  - TEE_ERROR_CORRUPT_OBJECT : If the object is corrupt. The object handle is
 *    closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, void *buffer,
                               uint32_t size)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The function TEE_TruncateObjectData changes the size of a data stream. If
 * size is less than the current size of the data stream then all bytes beyond
 * size are removed. If size is greater than the current size of the data stream
 * then the data stream is extended by adding zero bytes at the end of the
 * stream.
 * The object handle MUST have been opened with the write access permission.
 * This operation does not change the data position of any handle opened on the
 * object. Note that if the current data position of such a handle is beyond
 * size , the data position will point beyond the object data’s end after
 * truncation.
 * Truncating a data stream is atomic: Either the data stream is successfully
 * truncated or nothing happens.
 *
 * Parameters:
 *  - object : The object handle
 *  - size : The new size of the data stream
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_STORAGE_NO_SPACE : If insufficient storage space is available to
 *    perform the operation
 *  - TEE_ERROR_CORRUPT_OBJECT : If the object is corrupt. The object handle is
 *    closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * The TEE_SeekObjectData function sets the data position indicator associated
 * with the object handle.
 * The parameter whence controls the meaning of offset :
 *  - If whence is TEE_DATA_SEEK_SET , the data position is set to offset bytes
 *    from the beginning of the data stream.
 *  - If whence is TEE_DATA_SEEK_CUR , the data position is set to its current
 *    position plus offset .
 *  - If whence is TEE_DATA_SEEK_END , the data position is set to the size of
 *    the object data plus offset .
 * The TEE_SeekObjectData function may be used to set the data position beyond
 * the end of stream; this does not constitute an error. However, the data
 * position indicator does have a maximum value which is TEE_DATA_MAX_POSITION.
 * If the value of the data position indicator resulting from this operation
 * would be greater than TEE_DATA_MAX_POSITION, the error TEE_ERROR_OVERFLOW is
 * returned.
 * If an attempt is made to move the data position before the beginning of the
 * data stream, the data position is set at the beginning of the stream. This
 * does not constitute an error.
 *
 * Parameters:
 *  - object : The object handle
 *  - offset : The number of bytes to move the data position. A positive value
 *    moves the data position forward; a negative value moves the data position
 *    backward.
 *  - whence : The position in the data stream from which to calculate the new
 *    position
 *
 * Return Code:
 *  - TEE_SUCCESS : In case of success
 *  - TEE_ERROR_OVERFLOW : If the value of the data position indicator resulting
 *    from this operation would be greater than TEE_DATA_MAX_POSITION
 *  - TEE_ERROR_CORRUPT_OBJECT : If the object is corrupt. The object handle is
 *    closed.
 *  - TEE_ERROR_STORAGE_NOT_AVAILABLE : If the persistent object is stored in a
 *    storage area which is currently inaccessible.
 */
TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset,
                              TEE_Whence whence)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}
