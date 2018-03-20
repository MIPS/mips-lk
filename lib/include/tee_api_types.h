/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Based on GP TEE Internal API Specification Version 0.11 */
#ifndef TEE_API_TYPES_H
#define TEE_API_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <tee_api_defines.h>

/*
 * Common Definitions
 */

typedef uint32_t TEE_Result;

typedef struct {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[8];
} TEE_UUID;

/*
 * The TEE_Identity structure defines the full identity of a Client:
 * - login is one of the TEE_LOGIN_XXX constants
 * - uuid contains the client UUID or Nil if not applicable
 */
typedef struct {
    uint32_t login;
    TEE_UUID uuid;
} TEE_Identity;

/*
 * This union describes one parameter passed by the Trusted Core Framework
 * to the entry points TA_OpenSessionEntryPoint or
 * TA_InvokeCommandEntryPoint or by the TA to the functions
 * TEE_OpenTASession or TEE_InvokeTACommand.
 *
 * Which of the field value or memref to select is determined by the
 * parameter type specified in the argument paramTypes passed to the entry
 * point.
 */
typedef union {
    struct {
        void *buffer;
        size_t size;
    } memref;
    struct {
        uint32_t a;
        uint32_t b;
    } value;
} TEE_Param;

/*
 * The type of opaque handles on TA Session. These handles are returned by
 * the function TEE_OpenTASession.
 */
typedef struct __TEE_TASessionHandle *TEE_TASessionHandle;

/*
 * The type of opaque handles on property sets or enumerators. These
 * handles are either one of the pseudo handles TEE_PROPSET_XXX or are
 * returned by the function TEE_AllocatePropertyEnumerator.
 */
typedef struct __TEE_PropSetHandle *TEE_PropSetHandle;

/* Trusted Storage API for Data and Keys types */
typedef struct {
    uint32_t attributeID;
    union {
        struct {
            void *buffer;
            size_t length;
        } ref;
        struct {
            uint32_t a, b;
        } value;
    } content;
} TEE_Attribute;

typedef struct {
    uint32_t objectType;
    uint32_t objectSize;
    uint32_t maxObjectSize;
    uint32_t objectUsage;
    uint32_t dataSize;
    uint32_t dataPosition;
    uint32_t handleFlags;
} TEE_ObjectInfo;

typedef enum {
    TEE_DATA_SEEK_SET = 0,
    TEE_DATA_SEEK_CUR = 1,
    TEE_DATA_SEEK_END = 2
} TEE_Whence;

typedef uint32_t TEE_ObjectType;

typedef struct __TEE_ObjectHandle *TEE_ObjectHandle;

typedef struct __TEE_ObjectEnumHandle *TEE_ObjectEnumHandle;

/* Cryptographic Operations API */
typedef enum {
    TEE_MODE_ENCRYPT = 0,
    TEE_MODE_DECRYPT = 1,
    TEE_MODE_SIGN    = 2,
    TEE_MODE_VERIFY  = 3,
    TEE_MODE_MAC     = 4,
    TEE_MODE_DIGEST  = 5,
    TEE_MODE_DERIVE  = 6
} TEE_OperationMode;

typedef struct {
    uint32_t algorithm;
    uint32_t operationClass;
    uint32_t mode;
    uint32_t digestLength;
    uint32_t maxKeySize;
    uint32_t keySize;
    uint32_t requiredKeyUsage;
    uint32_t handleState;
} TEE_OperationInfo;

typedef struct {
    uint32_t keySize;
    uint32_t requiredKeyUsage;
} TEE_OperationInfoKey;

typedef struct {
    uint32_t algorithm;
    uint32_t operationClass;
    uint32_t mode;
    uint32_t digestLength;
    uint32_t maxKeySize;
    uint32_t handleState;
    uint32_t operationState;
    uint32_t numberOfKeys;
    TEE_OperationInfoKey keyInformation[];
} TEE_OperationInfoMultiple;

typedef struct __TEE_OperationHandle *TEE_OperationHandle;

/* Time API */
typedef struct {
    uint32_t seconds;
    uint32_t millis;
} TEE_Time;

/* Arithmetical API */
typedef uint32_t TEE_BigInt;
typedef uint32_t TEE_BigIntFMMContext;
typedef uint32_t TEE_BigIntFMM;

#endif /* TEE_API_TYPES_H */
