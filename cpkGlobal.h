#ifndef _CPKGLOBAL_H
#define	_CPKGLOBAL_H

#ifdef __cplusplus
extern "C" {
#endif


#define	CPK_SLOT_DESCRIPTION	"CPK Crypto Softtoken                                           \0"
#define	CPK_TOKEN_LABEL		"CPK PKCS#11 Software token     \0"
#define	CPK_TOKEN_SERIAL	"                "
#define	CPK_MANUFACTURER_ID	"Guan Zhi                       \0"



#include <pthread.h>
#include <security/cryptoki.h>
#include <security/pkcs11t.h>
#include "cpkPlatform.h"



/*
 * The following global variables are defined in cpkGeneral.c
 */
extern boolean_t cpktoken_initialized;
extern pthread_mutex_t cpk_giant_mutex;
extern struct slot cpk_slot;
extern struct obj_to_be_freed_list obj_delay_freed;
extern struct ses_to_be_freed_list ses_delay_freed;

#define	CPKTOKEN_SLOTID		8

/* CK_INFO: Information about cryptoki */
#define	CRYPTOKI_VERSION_MAJOR	2
#define	CRYPTOKI_VERSION_MINOR	20
#define	LIBRARY_DESCRIPTION	"CPK PKCS#11 Softtoken          \0"
#define	LIBRARY_VERSION_MAJOR	0
#define	LIBRARY_VERSION_MINOR	6


/* CK_SLOT_INFO: Information about our slot */
#define	HARDWARE_VERSION_MAJOR	0
#define	HARDWARE_VERSION_MINOR	0
#define	FIRMWARE_VERSION_MAJOR	0
#define	FIRMWARE_VERSION_MINOR	0

/* CK_TOKEN_INFO: More information about token */
#define	TOKEN_MODEL		"1.0             "
#define	MAX_PIN_LEN		0
#define	MIN_PIN_LEN		0



#ifdef	__cplusplus
}
#endif
#endif /* _CPKGLOBAL_H */
