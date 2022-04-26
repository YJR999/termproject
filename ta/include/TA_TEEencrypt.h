
#ifndef TA_TEEencrypt_H
#define TA_TEEencrypt_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_TEEencrypt_UUID { 0x23bffc88, 0x1811, 0x4e42, { 0x88, 0x4a, 0x27, 0x1b, 0xb5, 0xa3, 0x65, 0xf7} }

/* The function IDs implemented in this TA */

#define TA_TEEencrypt_ENCRYPT	10
#define TA_TEEencrypt_DECRYPT	11
#define TA_TEEencrypt_GENERATEKEY	12
#define TA_TEEencrypt_SENDKEY	13
#endif /*TA_TEEencrypt_H*/
