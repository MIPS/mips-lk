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

uint32_t TEE_BigIntFMMContextSizeInU32(uint32_t modulusSizeInBits)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

uint32_t TEE_BigIntFMMSizeInU32(uint32_t modulusSizeInBits)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Initialization Functions */
void TEE_BigIntInit(TEE_BigInt *bigInt, uint32_t len)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, uint32_t len,
                              TEE_BigInt *modulus)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, uint32_t len)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Converter Functions */
TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest, uint8_t *buffer,
                                            uint32_t bufferLen, int32_t sign)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_BigIntConvertToOctetString(void *buffer, uint32_t bufferLen,
                                          TEE_BigInt *bigInt)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Logical Operations */
int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

int32_t TEE_BigIntCmpS32(TEE_BigInt *op, int32_t shortVal)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, uint32_t bits)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Basic Arithmetic Operations */
void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r, TEE_BigInt *op1,
                   TEE_BigInt *op2)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Modular Arithmetic Operations */
void TEE_BigIntMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2,
                      TEE_BigInt *n)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2,
                      TEE_BigInt *n)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2,
                      TEE_BigInt *n)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Other Arithmetic Operations */
bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u, TEE_BigInt *v,
                                  TEE_BigInt *op1, TEE_BigInt *op2)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op, uint32_t confidenceLevel)
{
    return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Fast Modular Multiplication Operations */
void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, TEE_BigInt *src, TEE_BigInt *n,
                            TEE_BigIntFMMContext *context)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, TEE_BigIntFMM *src,
                              TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, TEE_BigIntFMM *op1,
                          TEE_BigIntFMM *op2, TEE_BigInt *n,
                          TEE_BigIntFMMContext *context)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}