#ifndef TA_TEST_SERVER_H
#define TA_TEST_SERVER_H

/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */

/* UUID : {7b9c56be-e448-11e5-9730-9a79f06e9478} */
#define TA_TEST_SERVER_UUID { 0x7b9c56be, 0xe448, 0x11e5,  \
    { 0x97, 0x30, 0x9a, 0x79, 0xf0, 0x6e, 0x94, 0x78 } }

/* UUID : {f74df2bd-58b6-4503-9aa1-f68fa8f31aa9} */
#define TA_TEST_CLIENT_UUID { 0xf74df2bd, 0x58b6, 0x4503, \
    { 0x9a, 0xa1, 0xf6, 0x8f, 0xa8, 0xf3, 0x1a, 0xa9 } }

/* UUID : {087446df-056a-450f-a08a-8cf8821eacab} */
#define TA_TEST_CLIENT2_UUID { 0x087446df, 0x056a, 0x450f, \
    { 0xa0, 0x8a, 0x8c, 0xf8, 0x82, 0x1e, 0xac, 0xab } }

/* UUID : {43f2be8e-e374-4251-949f-86082ee7e8a5} */
#define TA_TEST_STARTER_UUID { 0x43f2be8e, 0xe374, 0x4251, \
    { 0x94, 0x9f, 0x86, 0x08, 0x2e, 0xe7, 0xe8, 0xa5 } }

/* The TAFs ID implemented in this TA */
#define TA_HELLO_WORLD_CMD_INC_VALUE  0xbabadeda
#define TA_HELLO_WORLD_CMD_INC_MEMREF 0xbabadedb

#endif
