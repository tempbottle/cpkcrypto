#
# Gererated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add custumized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
CCADMIN=CCadmin
RANLIB=ranlib
CC=cc
CCC=CC
CXX=CC
FC=f77

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=build/Debug/Sun12-Solaris-x86

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/cpkSession.o \
	${OBJECTDIR}/cpkcrypto/cpk_map.o \
	${OBJECTDIR}/cpkcrypto/cpk_lib.o \
	${OBJECTDIR}/cpkcrypto/cpk_err.o \
	${OBJECTDIR}/cpkcrypto/cpk_pkcs7.o \
	${OBJECTDIR}/cpkSign.o \
	${OBJECTDIR}/cpkDecrypt.o \
	${OBJECTDIR}/cpkDecryptUtil.o \
	${OBJECTDIR}/cpkEncryptUtil.o \
	${OBJECTDIR}/cpkObjectUtil.o \
	${OBJECTDIR}/cpkRand.o \
	${OBJECTDIR}/main.o \
	${OBJECTDIR}/cpkSessionUtil.o \
	${OBJECTDIR}/cpkSignUtil.o \
	${OBJECTDIR}/cpkSlotToken.o \
	${OBJECTDIR}/cpkDualCrypt.o \
	${OBJECTDIR}/cpkObject.o \
	${OBJECTDIR}/cpkcrypto/ecies_err.o \
	${OBJECTDIR}/cpkKeys.o \
	${OBJECTDIR}/cpkVerifyUtil.o \
	${OBJECTDIR}/cpkAttributeUtil.o \
	${OBJECTDIR}/cpkcrypto/ecies_lib.o \
	${OBJECTDIR}/cpkGeneral.o \
	${OBJECTDIR}/cpkcrypto/ecies_kdf.o \
	${OBJECTDIR}/cpkEncrypt.o \
	${OBJECTDIR}/cpkPkcs11.o \
	${OBJECTDIR}/cpkVerify.o \
	${OBJECTDIR}/cpkcrypto/ecies_asn1.o \
	${OBJECTDIR}/cpkcrypto/cpk_asn1.o \
	${OBJECTDIR}/cpkDigest.o

# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=\
	openssl/lib/libcrypto.a \
	-lsocket

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS} dist/Debug/Sun12-Solaris-x86/pkcs11_cpk

dist/Debug/Sun12-Solaris-x86/pkcs11_cpk: ${OBJECTFILES}
	${MKDIR} -p dist/Debug/Sun12-Solaris-x86
	${LINK.c} -o dist/Debug/Sun12-Solaris-x86/pkcs11_cpk ${OBJECTFILES} ${LDLIBSOPTIONS} 

${OBJECTDIR}/cpkSession.o: cpkSession.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkSession.o cpkSession.c

${OBJECTDIR}/cpkcrypto/cpk_map.o: cpkcrypto/cpk_map.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/cpk_map.o cpkcrypto/cpk_map.c

${OBJECTDIR}/cpkcrypto/cpk_lib.o: cpkcrypto/cpk_lib.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/cpk_lib.o cpkcrypto/cpk_lib.c

${OBJECTDIR}/cpkcrypto/cpk_err.o: cpkcrypto/cpk_err.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/cpk_err.o cpkcrypto/cpk_err.c

${OBJECTDIR}/cpkcrypto/cpk_pkcs7.o: cpkcrypto/cpk_pkcs7.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/cpk_pkcs7.o cpkcrypto/cpk_pkcs7.c

${OBJECTDIR}/cpkSign.o: cpkSign.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkSign.o cpkSign.c

${OBJECTDIR}/cpkDecrypt.o: cpkDecrypt.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkDecrypt.o cpkDecrypt.c

${OBJECTDIR}/cpkDecryptUtil.o: cpkDecryptUtil.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkDecryptUtil.o cpkDecryptUtil.c

${OBJECTDIR}/cpkEncryptUtil.o: cpkEncryptUtil.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkEncryptUtil.o cpkEncryptUtil.c

${OBJECTDIR}/cpkObjectUtil.o: cpkObjectUtil.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkObjectUtil.o cpkObjectUtil.c

${OBJECTDIR}/cpkRand.o: cpkRand.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkRand.o cpkRand.c

${OBJECTDIR}/main.o: main.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/main.o main.c

${OBJECTDIR}/cpkSessionUtil.o: cpkSessionUtil.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkSessionUtil.o cpkSessionUtil.c

${OBJECTDIR}/cpkSignUtil.o: cpkSignUtil.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkSignUtil.o cpkSignUtil.c

${OBJECTDIR}/cpkSlotToken.o: cpkSlotToken.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkSlotToken.o cpkSlotToken.c

${OBJECTDIR}/cpkDualCrypt.o: cpkDualCrypt.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkDualCrypt.o cpkDualCrypt.c

${OBJECTDIR}/cpkObject.o: cpkObject.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkObject.o cpkObject.c

${OBJECTDIR}/cpkcrypto/ecies_err.o: cpkcrypto/ecies_err.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/ecies_err.o cpkcrypto/ecies_err.c

${OBJECTDIR}/cpkKeys.o: cpkKeys.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkKeys.o cpkKeys.c

${OBJECTDIR}/cpkVerifyUtil.o: cpkVerifyUtil.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkVerifyUtil.o cpkVerifyUtil.c

${OBJECTDIR}/cpkAttributeUtil.o: cpkAttributeUtil.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkAttributeUtil.o cpkAttributeUtil.c

${OBJECTDIR}/cpkcrypto/ecies_lib.o: cpkcrypto/ecies_lib.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/ecies_lib.o cpkcrypto/ecies_lib.c

${OBJECTDIR}/cpkGeneral.o: cpkGeneral.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkGeneral.o cpkGeneral.c

${OBJECTDIR}/cpkcrypto/ecies_kdf.o: cpkcrypto/ecies_kdf.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/ecies_kdf.o cpkcrypto/ecies_kdf.c

${OBJECTDIR}/cpkEncrypt.o: cpkEncrypt.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkEncrypt.o cpkEncrypt.c

${OBJECTDIR}/cpkPkcs11.o: cpkPkcs11.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkPkcs11.o cpkPkcs11.c

${OBJECTDIR}/cpkVerify.o: cpkVerify.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkVerify.o cpkVerify.c

${OBJECTDIR}/cpkcrypto/ecies_asn1.o: cpkcrypto/ecies_asn1.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/ecies_asn1.o cpkcrypto/ecies_asn1.c

${OBJECTDIR}/cpkcrypto/cpk_asn1.o: cpkcrypto/cpk_asn1.c 
	${MKDIR} -p ${OBJECTDIR}/cpkcrypto
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkcrypto/cpk_asn1.o cpkcrypto/cpk_asn1.c

${OBJECTDIR}/cpkDigest.o: cpkDigest.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g +w -Iopenssl/include -o ${OBJECTDIR}/cpkDigest.o cpkDigest.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf:
	${RM} -r build/Debug
	${RM} dist/Debug/Sun12-Solaris-x86/pkcs11_cpk

# Subprojects
.clean-subprojects:

# Enable dependency checking
.KEEP_STATE:
.KEEP_STATE_FILE:.make.state.${CONF}
