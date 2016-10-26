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

/* Generic Operation Functions */
TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
                                 uint32_t algorithm, uint32_t mode,
                                 uint32_t maxKeySize)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_GetOperationInfo(TEE_OperationHandle operation,
                          TEE_OperationInfo *operationInfo)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_GetOperationInfoMultiple(TEE_OperationHandle operation,
                                        TEE_OperationInfoMultiple
                                            *operationInfoMultiple,
                                        uint32_t *operationSize)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_ResetOperation(TEE_OperationHandle operation)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
                               TEE_ObjectHandle key)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation,
                                TEE_ObjectHandle key1, TEE_ObjectHandle key2)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_CopyOperation(TEE_OperationHandle dstOperation,
                       TEE_OperationHandle srcOperation)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Message Digest Functions */
void TEE_DigestUpdate(TEE_OperationHandle operation, void *chunk,
                      uint32_t chunkSize)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, void *chunk,
                             uint32_t chunkLen, void *hash, uint32_t *hashLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Symmetric Cipher Functions */
void TEE_CipherInit(TEE_OperationHandle operation, void *IV, uint32_t IVLen)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, void *srcData,
                            uint32_t srcLen, void *destData, uint32_t *destLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation, void *srcData,
                             uint32_t srcLen, void *destData,
                             uint32_t *destLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* MAC Functions */
void TEE_MACInit(TEE_OperationHandle operation, void *IV, uint32_t IVLen)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_MACUpdate(TEE_OperationHandle operation, void *chunk,
                   uint32_t chunkSize)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation, void *message,
                               uint32_t messageLen, void *mac,
                               uint32_t *macLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation, void *message,
                               uint32_t messageLen, void *mac,
                               uint32_t macLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Authenticated Encryption Functions */
TEE_Result TEE_AEInit(TEE_OperationHandle operation, void *nonce,
                      uint32_t nonceLen, uint32_t tagLen, uint32_t AADLen,
                      uint32_t payloadLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_AEUpdateAAD(TEE_OperationHandle operation, void *AADdata,
                     uint32_t AADdataLen)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, void *srcData,
                        uint32_t srcLen, void *destData, uint32_t *destLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation, void *srcData,
                              uint32_t srcLen, void *destData,
                              uint32_t *destLen, void *tag, uint32_t *tagLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation, void *srcData,
                              uint32_t srcLen, void *destData,
                              uint32_t *destLen, void *tag, uint32_t tagLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Asymmetric Functions */
TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
                                 TEE_Attribute *params, uint32_t paramCount,
                                 void *srcData, uint32_t srcLen,
                                 void *destData, uint32_t *destLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
                                 TEE_Attribute *params, uint32_t paramCount,
                                 void *srcData, uint32_t srcLen,
                                 void *destData, uint32_t *destLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
                                    TEE_Attribute *params, uint32_t paramCount,
                                    void *digest, uint32_t digestLen,
                                    void *signature, uint32_t *signatureLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
                                      TEE_Attribute *params,
                                      uint32_t paramCount, void *digest,
                                      uint32_t digestLen, void *signature,
                                      uint32_t signatureLen)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Key Derivation Functions */
void TEE_DeriveKey(TEE_OperationHandle operation, TEE_Attribute *params,
                   uint32_t paramCount, TEE_ObjectHandle derivedKey)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_GenerateRandom(void *randomBuffer, uint32_t randomBufferLen)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

