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

#ifndef TEE_INTERNAL_API_H
#define TEE_INTERNAL_API_H

/* TEE API */

/* TEE API data types */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tee_ta_api.h>

/* Property access functions */

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator,
                                 const char *name, bool *value);
TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
                                        const char *name, void *valueBuffer,
                                        size_t *valueBufferLen);
TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator,
                                     const char *name, TEE_Identity *value);
TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
                                   const char *name, char *valueBuffer,
                                   size_t *valueBufferLen);
TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator,
                                const char *name, uint32_t *value);
TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator,
                                 const char *name, TEE_UUID *value);
TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator);
void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator);
void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator,
                                 TEE_PropSetHandle propSet);
void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator);
TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator, void *nameBuffer,
                               size_t *nameBufferLen);
TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator);

/* System API - Misc */

__NO_RETURN void TEE_Panic(TEE_Result panicCode);
__NO_RETURN void _TEE_Panic(TEE_Result panicCode);

#define TEE_Panic(_code) do { \
    fprintf(stderr, "--- TEE_Panic (in %s:%d) 0x%lx ---\n", \
        __func__, __LINE__, (unsigned long)(_code)); \
    _TEE_Panic(_code); \
} while (0)

/* Internal Client API */
TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
                             uint32_t cancellationRequestTimeout,
                             uint32_t paramTypes,
                             TEE_Param params[TEE_NUM_PARAMS],
                             TEE_TASessionHandle *session,
                             uint32_t *returnOrigin);

void TEE_CloseTASession(TEE_TASessionHandle session);

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
                               uint32_t cancellationRequestTimeout,
                               uint32_t commandID, uint32_t paramTypes,
                               TEE_Param params[TEE_NUM_PARAMS],
                               uint32_t *returnOrigin);

/* System API - Cancellations */

bool TEE_GetCancellationFlag(void);

bool TEE_UnmaskCancellation(void);

bool TEE_MaskCancellation(void);

/* System API - Memory Management */

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer,
                                       size_t size);

void TEE_SetInstanceData(const void *instanceData);

void *TEE_GetInstanceData(void);

void *TEE_Malloc(size_t size, uint32_t hint);

void *TEE_Realloc(const void *buffer, uint32_t newSize);

void TEE_Free(void *buffer);

void *TEE_MemMove(void *dest, const void *src, uint32_t size);

int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, uint32_t size);

void *TEE_MemFill(void *buff, uint32_t x, uint32_t size);

/* Trusted Storage API for Data and Keys */

/* Generic Object Functions */
void TEE_GetObjectInfo(TEE_ObjectHandle object,
                       TEE_ObjectInfo *objectInfo);

TEE_Result TEE_GetObjectInfo1(TEE_ObjectHandle object,
                              TEE_ObjectInfo *objectInfo);

void TEE_RestrictObjectUsage(TEE_ObjectHandle object,
                             uint32_t objectUsage);

TEE_Result TEE_RestrictObjectUsage1(TEE_ObjectHandle object,
                                    uint32_t objectUsage);

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
                                        uint32_t attributeID, void *buffer,
                                        size_t *size);

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
                                       uint32_t attributeID, uint32_t *a,
                                       uint32_t *b);

void TEE_CloseObject(TEE_ObjectHandle object);

/* Transient Object Functions */
TEE_Result TEE_AllocateTransientObject(uint32_t objectType,
                                       uint32_t maxKeySize,
                                       TEE_ObjectHandle *object);

void TEE_FreeTransientObject(TEE_ObjectHandle object);

void TEE_ResetTransientObject(TEE_ObjectHandle object);

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
                                       const TEE_Attribute *attrs,
                                       uint32_t attrCount);

void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID,
                          const void *buffer, size_t length);

void TEE_InitValueAttribute(TEE_Attribute *attr, uint32_t attributeID,
                            uint32_t a, uint32_t b);

void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject,
                             TEE_ObjectHandle srcObject);
TEE_Result TEE_CopyObjectAttributes1(TEE_ObjectHandle destObject,
                                     TEE_ObjectHandle srcObject);

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
                           const TEE_Attribute *params, uint32_t paramCount);

/* Persistent Object Functions */
TEE_Result TEE_OpenPersistentObject(uint32_t storageID, const void *objectID,
                                    size_t objectIDLen, uint32_t flags,
                                    TEE_ObjectHandle *object);

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, const void *objectID,
                                      size_t objectIDLen, uint32_t flags,
                                      TEE_ObjectHandle attributes,
                                      const void *initialData,
                                      size_t initialDataLen,
                                      TEE_ObjectHandle *object);

void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object);
TEE_Result TEE_CloseAndDeletePersistentObject1(TEE_ObjectHandle object);

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object,
                                      const void *newObjectID,
                                      size_t newObjectIDLen);

/* Persistent Object Enumeration Functions*/
TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle
                                                  *objectEnumerator);

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);

TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle
                                                   objectEnumerator,
                                               uint32_t storageID);

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
                                       TEE_ObjectInfo *objectInfo,
                                       void *objectID, size_t *objectIDLen);

/* Data Stream Access Functions */
TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer,
                              size_t size, uint32_t *count);

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, const void *buffer,
                               size_t size);

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size);

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset,
                  TEE_Whence whence);

/* Cryptographic Operations API */

/* Generic Operation Functions */
TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
                                 uint32_t algorithm, uint32_t mode,
                                 uint32_t maxKeySize);

void TEE_FreeOperation(TEE_OperationHandle operation);

void TEE_GetOperationInfo(TEE_OperationHandle operation,
                          TEE_OperationInfo *operationInfo);

TEE_Result TEE_GetOperationInfoMultiple(TEE_OperationHandle operation,
                                        TEE_OperationInfoMultiple
                                            *operationInfoMultiple,
                                        size_t *operationSize);

void TEE_ResetOperation(TEE_OperationHandle operation);

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
                               TEE_ObjectHandle key);

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation,
                                TEE_ObjectHandle key1, TEE_ObjectHandle key2);

void TEE_CopyOperation(TEE_OperationHandle dstOperation,
                       TEE_OperationHandle srcOperation);

/* Message Digest Functions */
void TEE_DigestUpdate(TEE_OperationHandle operation, const void *chunk,
                      size_t chunkSize);

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, const void *chunk,
                             size_t chunkLen, void *hash, size_t *hashLen);

/* Symmetric Cipher Functions */
void TEE_CipherInit(TEE_OperationHandle operation, const void *IV,
                    size_t IVLen);

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, const void *srcData,
                            size_t srcLen, void *destData, size_t *destLen);

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
                             const void *srcData, size_t srcLen,
                             void *destData, size_t *destLen);

/* MAC Functions */
void TEE_MACInit(TEE_OperationHandle operation, const void *IV, size_t IVLen);

void TEE_MACUpdate(TEE_OperationHandle operation, const void *chunk,
                   size_t chunkSize);

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation,
                               const void *message, size_t messageLen,
                               void *mac, size_t *macLen);

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation,
                               const void *message, size_t messageLen,
                               const void *mac, size_t macLen);

/* Authenticated Encryption Functions */
TEE_Result TEE_AEInit(TEE_OperationHandle operation, const void *nonce,
                      size_t nonceLen, uint32_t tagLen, uint32_t AADLen,
                      uint32_t payloadLen);

void TEE_AEUpdateAAD(TEE_OperationHandle operation, const void *AADdata,
                     size_t AADdataLen);

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, const void *srcData,
                        size_t srcLen, void *destData, size_t *destLen);

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
                              const void *srcData, size_t srcLen,
                              void *destData, size_t *destLen, void *tag,
                              size_t *tagLen);

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
                              const void *srcData, size_t srcLen,
                              void *destData, size_t *destLen, void *tag,
                              size_t tagLen);

/* Asymmetric Functions */
TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
                                 const TEE_Attribute *params,
                                 uint32_t paramCount, const void *srcData,
                                 size_t srcLen, void *destData,
                                 size_t *destLen);

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
                                 const TEE_Attribute *params,
                                 uint32_t paramCount, const void *srcData,
                                 size_t srcLen, void *destData,
                                 size_t *destLen);

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
                                    const TEE_Attribute *params,
                                    uint32_t paramCount, const void *digest,
                                    size_t digestLen, void *signature,
                                    size_t *signatureLen);

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
                                      const TEE_Attribute *params,
                                      uint32_t paramCount, const void *digest,
                                      size_t digestLen, const void *signature,
                                      size_t signatureLen);

/* Key Derivation Functions */
void TEE_DeriveKey(TEE_OperationHandle operation,
                   const TEE_Attribute *params, uint32_t paramCount,
                   TEE_ObjectHandle derivedKey);

void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen);


/* Time API Functions */

void TEE_GetSystemTime(TEE_Time *time);

TEE_Result TEE_Wait(uint32_t timeout);

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);

TEE_Result TEE_SetTAPersistentTime(const TEE_Time *time);

void TEE_GetREETime(TEE_Time *time);


/* Arithmetical API */

/* Memory Allocation and Size of Objects */
#define TEE_BigIntSizeInU32(n) ((((n)+31)/32)+2)

size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits);

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits);

/* Initialization Functions */
void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len);

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, size_t len,
                              const TEE_BigInt *modulus);

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len);

/* Converter Functions */
TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest,
                                            const uint8_t *buffer,
                                            size_t bufferLen, int32_t sign);

TEE_Result TEE_BigIntConvertToOctetString(uint8_t *buffer, size_t *bufferLen,
                                          const TEE_BigInt *bigInt);

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal);

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, const TEE_BigInt *src);

/* Logical Operations */
int32_t TEE_BigIntCmp(const TEE_BigInt *op1, const TEE_BigInt *op2);

int32_t TEE_BigIntCmpS32(const TEE_BigInt *op, int32_t shortVal);

void TEE_BigIntShiftRight(TEE_BigInt *dest, const TEE_BigInt *op, size_t bits);

bool TEE_BigIntGetBit(const TEE_BigInt *src, uint32_t bitIndex);

uint32_t TEE_BigIntGetBitCount(const TEE_BigInt *src);

/* Basic Arithmetic Operations */
void TEE_BigIntAdd(TEE_BigInt *dest, const TEE_BigInt *op1,
                   const TEE_BigInt *op2);

void TEE_BigIntSub(TEE_BigInt *dest, const TEE_BigInt *op1,
                   const TEE_BigInt *op2);

void TEE_BigIntNeg(TEE_BigInt *dest, const TEE_BigInt *op);

void TEE_BigIntMul(TEE_BigInt *dest, const TEE_BigInt *op1,
                   const TEE_BigInt *op2);

void TEE_BigIntSquare(TEE_BigInt *dest, const TEE_BigInt *op);

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
                   const TEE_BigInt *op1, const TEE_BigInt *op2);

/* Modular Arithmetic Operations */
void TEE_BigIntMod(TEE_BigInt *dest, const TEE_BigInt *op,
                   const TEE_BigInt *n);

void TEE_BigIntAddMod(TEE_BigInt *dest, const TEE_BigInt *op1,
                      const TEE_BigInt *op2, const TEE_BigInt *n);

void TEE_BigIntSubMod(TEE_BigInt *dest, const TEE_BigInt *op1,
                      const TEE_BigInt *op2, const TEE_BigInt *n);

void TEE_BigIntMulMod(TEE_BigInt *dest, const  TEE_BigInt *op1,
                      const TEE_BigInt *op2, const TEE_BigInt *n);

void TEE_BigIntSquareMod(TEE_BigInt *dest, const TEE_BigInt *op,
                         const TEE_BigInt *n);

void TEE_BigIntInvMod(TEE_BigInt *dest, const TEE_BigInt *op,
                      const TEE_BigInt *n);

/* Other Arithmetic Operations */
bool TEE_BigIntRelativePrime(const TEE_BigInt *op1, const TEE_BigInt *op2);

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
                                  TEE_BigInt *v, const TEE_BigInt *op1,
                                  const TEE_BigInt *op2);

int32_t TEE_BigIntIsProbablePrime(const TEE_BigInt *op,
                                  uint32_t confidenceLevel);

/* Fast Modular Multiplication Operations */
void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, const TEE_BigInt *src,
                            const TEE_BigInt *n,
                            const TEE_BigIntFMMContext *context);

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, const TEE_BigIntFMM *src,
                              const TEE_BigInt *n,
                              const TEE_BigIntFMMContext *context);

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, const TEE_BigIntFMM *op1,
                          const TEE_BigIntFMM *op2, const TEE_BigInt *n,
                          const TEE_BigIntFMMContext *context);

#endif
