/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#ifdef __gnu_linux__
    #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "patchfinder64.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

static uint32_t arm64_branch_instruction(uintptr_t from, uintptr_t to) {
  return from > to ? 0x18000000 - (from - to) / 4 : 0x14000000 + (to - from) / 4;
}

// iOS 15 "%s: firmware validation failed %d\" @%s:%d SPU Firmware Validation Patch
int get_SPUFirmwareValidation_patch(void *kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    char rootvpString[43] = "\"%s: firmware validation failed %d\" @%s:%d";
    void* ent_loc = memmem(kernel_buf,kernel_len,rootvpString,42);
    if(!ent_loc) {
        printf("%s: Could not find \"%%s: firmware validation failed %%d\" @%%s:%%d string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s: firmware validation failed %%d\" @%%s:%%d\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"%%s: firmware validation failed %%d\" @%%s:%%d xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s: firmware validation failed %%d\" @%%s:%%d\" ref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
        printf("%s: Could not find firmware validation function start\n",__FUNCTION__);
        return -1;
    }
    xref_stuff = xref64code(kernel_buf,0,(addr_t)GET_OFFSET(kernel_len, beg_func), beg_func);
    if(!xref_stuff) {
        printf("%s: Could not find previous xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found function xref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t next_bl = step64_back(kernel_buf, xref_stuff, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64_back(kernel_buf, (next_bl - 0x4), 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64_back(kernel_buf, (next_bl - 0x4), 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    beg_func = bof64(kernel_buf,0,next_bl);
    if(!beg_func) {
        printf("%s: Could not find start of firmware validation function\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching SPU Firmware Validation at %p\n\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0;
    return 0;
}

// iOS 15 rootvp not authenticated after mounting Patch
int get_RootVPNotAuthenticatedAfterMounting_patch(void *kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char rootVPString[40] = "rootvp not authenticated after mounting";
    char md0String[3] = "md0";
    void* ent_loc = memmem(kernel_buf,kernel_len,md0String,3);
    if(!ent_loc) {
        printf("%s: Could not find \"md0\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"md0\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff_md = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff_md) {
        printf("%s: Could not find \"md0\" xref\n",__FUNCTION__);
        return -1;
    }
    // this path wasn't working so i had to do this, the cbz before md0
    /*
    printf("%s: Found \"md0\" ref at %p\n",__FUNCTION__,(void*)xref_stuff_md);
    addr_t next_bl = step64(kernel_buf, xref_stuff_md + 0x8, 100, INSN_CALL);
    if(!next_bl) {
        // Newer devices will fail here, so using another string is required
        printf("%s: Failed to use \"md0\", swapping to \"rootvp not authenticated after mounting\"\n",__FUNCTION__);
        ent_loc = memmem(kernel_buf,kernel_len,rootVPString,39);
        if(!ent_loc) {
            printf("%s: Could not find \"rootvp not authenticated after mounting\" string\n",__FUNCTION__);
            return -1;
        }
        printf("%s: Found \"rootvp not authenticated after mounting\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
        addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
        if(!xref_stuff) {
            printf("%s: Could not find \"rootvp not authenticated after mounting\" xref\n",__FUNCTION__);
            return -1;
        }
        printf("%s: Found \"rootvp not authenticated after mounting\" str xref at %p\n",__FUNCTION__,(void*)xref_stuff);
        addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
        if(!beg_func) {
            printf("%s: Could not find function start\n",__FUNCTION__);
            return -1;
        }
        beg_func = beg_func + 0xA98;
        printf("%s: Found function start at %p\n",__FUNCTION__,(void*)beg_func);
        next_bl = step64(kernel_buf, beg_func, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    } else {
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }

    printf("%s: Patching ROOTVP at %p\n\n", __FUNCTION__,(void*)(next_bl + 0x4));
    *(uint32_t *) (kernel_buf + next_bl + 0x4) = 0xD503201F;
    */
    
    printf("%s: Patching ROOTVP at %p\n\n", __FUNCTION__,(void*)(xref_stuff_md + 0xC));
    // bl #0x243934 to movz x0, #0x1
    *(uint32_t *) (kernel_buf + xref_stuff_md - 0xC) = 0xD2800020;

    // bl #0xffffffffffbf0714 (strncmp) to movz x0, #0
    *(uint32_t *) (kernel_buf + xref_stuff_md + 0x18) = 0xD2800000;
    return 0;
}

// iOS 15 AMFI Kernel Patch
int get_AMFIInitializeLocalSigningPublicKey_patch(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    char AMFIString[52] = "\"AMFI: %s: unable to obtain local signing public key";
    void* ent_loc = memmem(kernel_buf,kernel_len,AMFIString,51);
    if(!ent_loc) {
        printf("%s: Could not find \"AMFI: %%s: unable to obtain local signing public key\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"AMFI: %%s: unable to obtain local signing public key\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"AMFI: %%s: unable to obtain local signing public key\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"AMFI: %%s: unable to obtain local signing public key ref at %p\n",__FUNCTION__,(void*)xref_stuff);

    printf("%s: Patching \"Local Signing Public Key\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff + 0x4));
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0xD503201F;
    
    return 0;
}

// tested on an ipad 6 on ios 13.7, this was done to avoid wait like 2 or 10 minutes when it is booting
int disableTouchidSensor(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    addr_t xref_stuff;
    addr_t beg_func;
    void *str_stuff;

    printf("[*] Patching AppleBiometricSensor\n");
    str_stuff = memmem(kernel_buf, kernel_len, "_sepTransactResponse", 21);
    if (!str_stuff)
    {
        printf("[-] Failed to find _sepTransactResponse\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000; // mov w0, #0
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F0FFF; // retab
    printf("[+] Patched AppleBiometricSensor\n");

    return 0;
}

// cryptex validation patch (improved)
int cryptex_patch(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    addr_t xref_stuff;
    addr_t xref_stuff2;
    addr_t xref_stuff3;
    addr_t beg_func;
    addr_t beg_func2;
    addr_t beg_func3;
    void *str_stuff;
    void *str_stuff2;
    void *str_stuff3;
    printf("[*] Patching Img4DecodeGetPropertyData\n");
    str_stuff = memmem(kernel_buf, kernel_len, "Img4DecodeGetPropertyData: [%d %s]", 34);
    if (!str_stuff)
    {
        printf("[-] Failed to find Img4DecodeGetPropertyData\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000; // mov w0, #0
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    printf("[+] Patched Img4DecodeGetPropertyData\n");
    return 0;
}

// based on seprmvr, thank you so much mineek, i implemented it because here are linux users. 
int fuck_the_sep(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    addr_t xref_stuff;
    addr_t beg_func;
    void *str_stuff;
    
    void* xnu_vers = memmem(kernel_buf,kernel_len,"root:xnu-",9);
    int kernel_vers = atoi(xnu_vers+9);

    printf("[*] Patching sks timeout strike\n");
    str_stuff = memmem(kernel_buf, kernel_len, "AppleKeyStore: sks timeout strike %d", 36);
    if (!str_stuff)
    {
        printf("[-] Failed to find sks timeout strike\n");
        return -1;
    }

    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched sks timeout strike\n");

    printf("[*] Patching SEP Panicked\n");
    str_stuff = memmem(kernel_buf, kernel_len, "\x1b[35m ***** SEP Panicked! dumping log. *****\x1b[0m", 36);
    // on ios 12.4 kernel sep panicked not work for me. so it just jump this. 
    int errorsad = 1;
    if (!str_stuff)
    {
        printf("[-] Failed to find SEP Panicked\n");
        errorsad = 0;
    }

    if (errorsad == 1)
    {
        xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
        beg_func = bof64(kernel_buf, 0, xref_stuff);
        *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
        *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
        printf("[+] Patched SEP Panicked\n");
    }
    
    printf("[*] Patching AppleKeyStore: operation failed\n");
    str_stuff = memmem(kernel_buf, kernel_len, "AppleKeyStore: operation %s(pid: %d se", 38);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleKeyStore: operation failed\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    while (*(uint32_t *)(kernel_buf + xref_stuff) != 0xD63F0100)
    {
        xref_stuff -= 0x4;
    }
    *(uint32_t *)(kernel_buf + xref_stuff) = 0xD2800000;
    printf("[+] Patched AppleKeyStore: operation failed\n");

    if (kernel_vers == 4903) {
        // did everything needed already for iOS 12
        printf("%s: quitting...\n", __FUNCTION__);
        return 0;
    }

    printf("[*] Patching AppleMesaSEPDriver\n");
    str_stuff = memmem(kernel_buf, kernel_len, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 66);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleMesaSEPDriver\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleMesaSEPDriver\n");

    //AppleSEP:WARNING: EP0 received unsolicited message
    printf("[*] Patching AppleSEP:WARNING: EP0 received unsolicited message\n");
    str_stuff = memmem(kernel_buf, kernel_len, "AppleSEP:WARNING: EP0 received unsolicited message", 48);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleSEP:WARNING: EP0 received unsolicited message\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleSEP:WARNING: EP0 received unsolicited message\n");

    //SEP/OS failed to boot at stage
    printf("[*] Patching SEP/OS failed to boot at stage\n");
    str_stuff = memmem(kernel_buf, kernel_len, "\"SEP/OS failed to boot at stage %d\\nFirmware type: %s\"@/BuildRoot/Library/Caches/com.apple.xbs/Sources/AppleSEPManager", 96);
    if (!str_stuff)
    {
        printf("[-] Failed to find SEP/OS failed to boot at stage\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched SEP/OS failed to boot at stage\n");

    //AppleBiometricSensor: RECOVERY: Reason %d, Last command 0x%x
    printf("[*] Patching AppleBiometricSensor: RECOVERY\n");
    str_stuff = memmem(kernel_buf, kernel_len, "AppleBiometricSensor: RECOVERY: Reason %d, Last command 0x%x", 57);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleBiometricSensor: RECOVERY\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleBiometricSensor: RECOVERY\n");

    //ERROR: %s: _sensorErrorCounter:%u --> reset\n
    printf("[*] Patching _sensorErrorCounter: --> reset\n");
    str_stuff = memmem(kernel_buf, kernel_len, "ERROR: %s: _sensorErrorCounter:%u --> reset\\n", 41);
    if (!str_stuff)
    {
        printf("[-] Failed to find _sensorErrorCounter: --> reset\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched _sensorErrorCounter: --> reset\n");
    
    //ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d\n\n
    printf("[*] Patching ERROR: AssertMacros\n");
    str_stuff = memmem(kernel_buf, kernel_len, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 66);
    if (!str_stuff)
    {
        printf("[-] Failed to find ERROR: AssertMacros\n");
        return -1;
    }
    int done = 0;
    while (!done)
    {
        xref_stuff = xref64(kernel_buf, xref_stuff + 1, kernel_len, (addr_t)GET_OFFSET(klen, str_stuff));
        if (xref_stuff == 0)
        {
            done = 1;
            break;
        }
        beg_func = bof64(kernel_buf, 0, xref_stuff);
        if (*(uint32_t *)(kernel_buf + beg_func + 0x18) == 0xb4000293)
        {
            printf("[+] Skipped ERROR: AssertMacros at 0x%llx\n", beg_func);
            continue;
        }
        *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
        *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
        printf("[+] Patched ERROR: AssertMacros at 0x%llx\n", beg_func);
    }
    printf("[+] Patched ERROR: AssertMacros\n");
    printf("%s: quitting...\n", __FUNCTION__);

    return 0;

}

// aslr
int pathAslr(void* kernel_buf,size_t kernel_len) {
    
    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[7] = "__XHDR";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_sig_check_string, 7);
    if(!ent_loc) {
        printf("%s: Could not find \"__XHDR, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"__XHDR\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len, ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find \"__XHDR\" xref\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found \"__XHDR\" xref at %p\n",__FUNCTION__,(void*)ent_ref);
    addr_t start_func = bof64(kernel_buf,0, ent_ref);
    if(!start_func) {
        printf("%s: Could not find load load_code_signature start\n",__FUNCTION__);
        return -1;
    }

    // check for ios 15
    uint32_t tbnz1_ref = step64_back(kernel_buf, (start_func + 0x374), 150 * 4, 0x36000000, 0x7E000000);
    uint32_t instMemValToCheck = *((uint32_t *)(kernel_buf + (tbnz1_ref - 0x4))); // on ios 15 before the tbnz function it has the ldrb function that we need to path

    if (instMemValToCheck == 0x394122C8)
    {
        printf("ios 15 Detected!\n");
        printf("%s: Patched ldrb    w8, [x22, #0x48] to mov x8, #0x20 at %p\n",__FUNCTION__, (void*) tbnz1_ref);
        *((uint32_t *)(kernel_buf + (tbnz1_ref - 0x4))) = 0xD2800408;
        return 0;
    }
    
    ent_ref = xref64code(kernel_buf,0,(addr_t)GET_OFFSET(kernel_len, start_func), start_func);
    if(!ent_ref) {
        printf("%s: Could not find load_code_signature xref to load_machfile\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found function xref at %p\n",__FUNCTION__,(void*)ent_ref);

    addr_t tbnz_ref = step64_back(kernel_buf, ent_ref, 150 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    uint32_t memValToCheck = *((uint32_t *)(kernel_buf + (tbnz_ref - 0x8))); // ios 14 is 8 bytes before
    uint32_t memValToCheck4 = *((uint32_t *)(kernel_buf + (tbnz_ref - 0x4))); // ios 13 is 4 bytes before
    
    if ((memValToCheck == 0xd2800408) || (memValToCheck4 == 0xd2800419) || (memValToCheck4 == 0xd2800408)) {
        printf("Detected, ASLR was already patched Omitting\n");
        return 0;
    } else if (memValToCheck == 0x394122c8) {
        *((uint32_t *)(kernel_buf + (tbnz_ref - 0x8))) = 0xd2800408; // ios 14 the ldrb instruction to path is 8 byte before the tbnz
    } else if (memValToCheck4 == 0x394122c8) {
        *((uint32_t *)(kernel_buf + (tbnz_ref - 0x4))) = 0xd2800408; // ios 13 the ldrb instruction to path is 4 byte before the tbnz
    } else if (memValToCheck4 == 0xb9404a99) {
        *((uint32_t *)(kernel_buf + (tbnz_ref - 0x4))) = 0xd2800419; // ios 11 the ldr instruction to path is 4 byte before the tbnz and it uses w25.
    } else {
        printf("we couldn't find the instruction to path");
        return -1;
    }

    printf("%s: Patched ldrb    w8, [x22, #0x48] at %p\n",__FUNCTION__, (void*) tbnz_ref);
    return 0;
}

size_t find_pattern(const unsigned char *buffer, size_t buflen, const unsigned char *pattern, const unsigned char *mask, size_t pattern_len) {
    size_t i, j;

    for (i = 0; i < buflen - pattern_len + 1; ++i) {
        for (j = 0; j < pattern_len; ++j) {
            if ((buffer[i + j] & mask[j]) != (pattern[j] & mask[j])) {
                break;
            }
        }
        if (j == pattern_len) {
            printf("Pattern found at offset: %zu\n", i);
            //printf("value in hexadecimal: %p\n", (void *)buffer[i]);
            return i;
        }
    }
    return 0; // Return 0 if pattern is not found
}

int pathPtrace(void* kernel_buf,size_t kernel_len) {
    printf("looking for the bytes in %p\n", kernel_buf);
    unsigned char pattern[] = { 0xB3, 0x62, 0x01, 0x91, 0xE0, 0x03, 0x13, 0xAA, 0x35, 0x7B, 0xF3, 0x97, 0xA8, 0x6A, 0x42, 0xB9, 0x68, 0x29, 0x50, 0x37, 0x08, 0x01, 0x14, 0x32 }; // ios 15
    unsigned char mask[]    = { 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x0F, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xF0, 0x00, 0xF0, 0xFF, 0x0F, 0x00, 0xF0, 0xFF, 0x00, 0xF0, 0xFF, 0xFF };
    
    unsigned char pattern14[] = { 0xE0, 0x03, 0x15, 0xAA, 0x02, 0x00, 0x80, 0x52, 0x08, 0x11, 0xF4, 0x97, 0x88, 0x4A, 0x41, 0xB9, 0xA8, 0xFC, 0x57, 0x37, 0x08, 0x01, 0x14, 0x32 };
    unsigned char mask14[] =    { 0xF0, 0xFF, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xF0, 0xFF, 0x00, 0x00, 0xF0, 0xFF, 0x00, 0xF0, 0xFF, 0xFF };

    unsigned char pattern13[] = { 0xE0, 0x03, 0x15, 0xAA, 0x02, 0x00, 0x80, 0x52, 0x08, 0x11, 0xF4, 0x97, 0x88, 0x4A, 0x41, 0xB9, 0xA8, 0xFC, 0x57, 0x37, 0x08, 0x01, 0x14, 0x32 };
    unsigned char mask13[] =    { 0xF0, 0xFF, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xF0, 0xFF, 0x00, 0x00, 0xF0, 0xFF, 0x00, 0xF0, 0xFF, 0xFF };
    /* // ios 15
        add x19, x21, #0x58
        mov x0, x19
        bl #0xffffffffffcdecdc // pc + 0xffffffffffcdecdc
        ldr w8, [x21, #0x268]
        tbnz w8, #0xa, #0x53c // pc + 0x53c
    */

    size_t pattern_len = sizeof(pattern);
    size_t buffer = find_pattern(kernel_buf, kernel_len, pattern, mask, pattern_len);

    if (buffer != 0) {
        //printf("Byte value at address %p: 0x%02X\n", (void *)(kernel_buf + buffer), *(unsigned char *)(kernel_buf + buffer + 12));
        *(uint32_t *) (kernel_buf + buffer + 12) = 0x52800008;
        *(uint32_t *) (kernel_buf + buffer + 16) = 0xd503201f;

        printf("Patching \"ptrace debugger method\"\n\n");
        return 0;
    } else {
        printf("We couldn't found the bytes of ptrace path, we are going to try with bytes for ios 14\n");
    }
    
    size_t pattern_len14 = sizeof(pattern14);
    buffer = find_pattern(kernel_buf, kernel_len, pattern14, mask14, pattern_len14);

    if (buffer != 0) {
        *(uint32_t *) (kernel_buf + buffer - 0x70) = 0xd2800000;
        *(uint32_t *) (kernel_buf + buffer - 0x6C) = 0x14000025; // b 0x94 to return correctly

        printf("Patching \"ptrace debugger method\"\n\n");
        return 0;
    } else {
        printf("We couldn't found the bytes of ptrace path for ios 14, we are going to try with bytes for ios 13\n");
    }



    size_t pattern_len13 = sizeof(pattern13);
    buffer = find_pattern(kernel_buf, kernel_len, pattern13, mask13, pattern_len13);

    if (buffer != 0) {

        *(uint32_t *) (kernel_buf + buffer - 0x8C) = 0xd2800000;
        *(uint32_t *) (kernel_buf + buffer - 0x88) = 0x140000ac; // b 0x2B0 to return correctly

        printf("Patching \"ptrace debugger method\"\n\n");
        return 0;
    } else {
        printf("We couldn't found the bytes of ptrace path for ios 13\n");
    }

    return -1;
}

int panic007Path(void* kernel_buf,size_t kernel_len) {
    unsigned char pattern[] = { 0x2a, 0x7d, 0x09, 0x53, 0x4a, 0x01, 0x1c, 0x12, 0x2b, 0x79, 0x1f, 0x53, 0x6b, 0x01, 0x15, 0x12, 0x68, 0x01, 0x08, 0x2a, 0x08, 0x01, 0x0a, 0x2a};
    unsigned char mask[]    = { 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xf0, 0xff, 0x00, 0xff, 0xf0, 0xff };
    
    size_t pattern_len = sizeof(pattern);
    size_t buffer = 0x0;
    buffer = find_pattern(kernel_buf, kernel_len, pattern, mask, pattern_len);
    
    if (buffer == 0) {
        printf("We couldn't found the bytes of panic007 path\n");
        return -1;
    }

    *(uint32_t *) (kernel_buf + buffer + 0x10) = 0xd503201f;
    
    printf("panic007 path applied\n");
}

int pathSnapshot(void* kernel_buf,size_t kernel_len) { // ios 15.8.2 iphone8,1 kernel

    printf("%s: Entering ...\n",__FUNCTION__);

    const char failed_to_jhash_insert[] = "%s:%d: %s failed to jhash_insert the root inode, error %d";
    void* ent_loc = memmem(kernel_buf,kernel_len,failed_to_jhash_insert,strlen(failed_to_jhash_insert));
    if(!ent_loc) {
        printf("%s: Could not find \"Failed to jhash_insert the root inode\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"Failed to jhash_insert the root inode\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"apfs_vfsop_mount\" xref\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found \"apfs_vfsop_mount call to Failed to jhash_insert the root inode str\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    printf("%s: Patching \"snapshot\" at %p\n\n", __FUNCTION__,(void*)(ent_ref + 0x14));
    
    uint32_t instMemValToCheck = *((uint32_t *)(kernel_buf + (ent_ref + 0x14))); // on ios 15 should be ldr w8, [sp, #0x80]
    if (instMemValToCheck != 0xb94083e8) {// e88340b9
        printf("[!] couldn't found the correct instruction to path snapshot at");
        return 0;
    }

    *(uint32_t *) (kernel_buf + ent_ref + 0x14) = 0xd2800008;
    return 0;
}

// load firmware which are not signed like AOP.img4, Homer.img4, etc. ios 15
int bypassFirmwareValidate15(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[23] = "firmware authenticated";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_sig_check_string,23);
    if(!ent_loc) {
        printf("%s: Could not find \"firmware authenticated, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"firmware authenticated\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"firmware authenticated\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"firmware authenticated\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    printf("%s: Patching \"firmware authenticated\" at %p\n\n", __FUNCTION__,(void*)(ent_ref + 0x24));
    *(uint32_t *) (kernel_buf + ent_ref + 0x24) = 0xd2800000;

    return 0;
}

// load firmware which are not signed like AOP.img4, Homer.img4, etc. ios 14
int bypassFirmwareValidate(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[55] = "Img4DecodePerformTrustEvaluationWithCallbacks: [%d %s]";
    void* found = memmem(kernel_buf,kernel_len,img4_sig_check_string,54);
    if(!found) {
        printf("%s: Could not find \"%%s::%%s() Img4DecodePerformTrustEvaluationWithCallbacks\" string\n",__FUNCTION__);
        return -1;
    }

    char img4_wrapped_Image4_payload[27] = "trust evaluation succeeded";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_wrapped_Image4_payload,26);
    if(!ent_loc) {
        printf("%s: Could not find \"trust evaluation succeeded\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"trust evaluation succeeded\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"trust evaluation succeeded\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"trust evaluation succeeded\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    // Search backward for the BL (branch-and-link) to the validation function
    addr_t validation_bl = step64_back(kernel_buf, ent_ref, 100 * 4, 0xFC000000, 0xFC000000); // BL mask
    if(!validation_bl) {
        printf("%s: Could not find validation BL, trying conditional branch\n",__FUNCTION__);
        // Try to find a CBZ/CBNZ that gates the error path instead
        addr_t cbz_ref = step64_back(kernel_buf, ent_ref, 50 * 4, 0x34000000, 0x7E000000);
        if(cbz_ref) {
            printf("%s: Found conditional branch at %p, NOPing it\n",__FUNCTION__,(void*)cbz_ref);
            *(uint32_t *)(kernel_buf + cbz_ref) = 0xd503201f;
            return 0;
        }
        printf("%s: Could not find any viable patch point\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found validation call at %p\n",__FUNCTION__,(void*)validation_bl);
    
    // NOP out the BL (replace with NOP so it skips the validation call entirely)
    printf("%s: NOPing validation call at %p\n",__FUNCTION__,(void*)validation_bl);
    *(uint32_t *)(kernel_buf + validation_bl) = 0xd503201f;

    return 0;
}

// load firmware which are not signed like AOP.img4, Homer.img4, etc. ios 13
int bypassFirmwareValidate13(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char first_string[45] = "Image4: Encrypted payloads are not supported";
    void* found = memmem(kernel_buf,kernel_len,first_string,44);
    if(!found) {
        printf("%s: Could not find \"Image4: Encrypted payloads are not supported, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"Image4: Encrypted payloads are not supported\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,found));
    addr_t found_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, found));

    if(!found_ref) {
        printf("%s: Could not find \"xref of Image4: Encrypted payloads are not supported\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"Image4: Encrypted payloads are not supported\" xref at %p\n",__FUNCTION__,(void*)found);

    printf("%s: Patching \"patching step 1\" at %p\n\n", __FUNCTION__,(void*)(found_ref + 0x50));
    *(uint32_t *) (kernel_buf + found_ref + 0x50) = 0xd503201f;
    printf("%s: Patching \"patching step 2\" at %p\n\n", __FUNCTION__,(void*)(found_ref - 0x50));
    *(uint32_t *) (kernel_buf + found_ref - 0x50) = 0xd503201f;

   char second_string[34] = "Image4: Payload hash check failed";
    void* second_found = memmem(kernel_buf,kernel_len,second_string,33);
    if(!second_found) {
        printf("%s: Could not find \"Image4: Payload hash check failed, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"Image4: Payload hash check failed\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,second_found));
    addr_t second_found_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, second_found));

    if(!second_found_ref) {
        printf("%s: Could not find \"xref of Image4: Payload hash check failed\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"Image4: Payload hash check failed\" xref at %p\n",__FUNCTION__,(void*)second_found_ref);

    printf("%s: Patching \"patching step 3\" at %p\n\n", __FUNCTION__,(void*)(second_found_ref - 0x08));
    *(uint32_t *) (kernel_buf + second_found_ref - 0x08) = 0x17ffff96;

    return 0;
}

//iOS 14 AppleFirmwareUpdate img4 signature check
int get_AppleFirmwareUpdate_img4_signature_check(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[56] = "%s::%s() Performing img4 validation outside of workloop";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_sig_check_string,55);
    if(!ent_loc) {
        printf("%s: Could not find \"%%s::%%s() Performing img4 validation outside of workloop\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s::%%s() Performing img4 validation outside of workloop\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"%%s::%%s() Performing img4 validation outside of workloop\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s::%%s() Performing img4 validation outside of workloop\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    printf("%s: Patching \"%%s::%%s() Performing img4 validation outside of workloop\" at %p\n\n", __FUNCTION__,(void*)(ent_ref + 0xc));
    *(uint32_t *) (kernel_buf + ent_ref + 0xc) = 0xD2800000;

    return 0;
}

static addr_t
cbz_ref64_back(const uint8_t *buf, addr_t start, size_t length) {

    //find cbz/cbnz
    uint32_t cbz_mask = 0x7E000000;
    uint32_t instr = 0;
    uint32_t imm = 0;
    addr_t cbz = start;
    while (cbz) {
        instr = *(uint32_t *) (buf + cbz);
        if ((instr & cbz_mask) == 0x34000000) {
            imm = ((instr & 0x00FFFFFF) >> 5) << 2;
            if (cbz + imm == start)
                return cbz;
        }
        cbz -= 4;
    }
    return 0;
}

//iOS 15 "could not authenticate personalized root hash!" patch
int get_could_not_authenticate_personalized_root_hash_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    //get target offset for new branch
    char roothash_authenticated_string[sizeof("successfully validated on-disk root hash")] = "successfully validated on-disk root hash";

    unsigned char *roothash_authenticated_loc = memmem(kernel_buf, kernel_len, roothash_authenticated_string, sizeof("successfully validated on-disk root hash") - 1);
    if(!roothash_authenticated_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, roothash_authenticated_string);
        return -1;
    }

    for (; *roothash_authenticated_loc != 0; roothash_authenticated_loc--);
    roothash_authenticated_loc++;
    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, roothash_authenticated_string, GET_OFFSET(kernel_len, roothash_authenticated_loc));

    addr_t roothash_authenticated_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, roothash_authenticated_loc));
    if(!roothash_authenticated_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, roothash_authenticated_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, roothash_authenticated_string, (void*) roothash_authenticated_ref);

    //get previous cbz
    addr_t branch_target = step64_back(kernel_buf, roothash_authenticated_ref, 20 * 4, 0x34000000, 0x7E000000);
    if(!branch_target) {
        printf("%s: Could not find previous cbz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found previous cbz at %p\n",__FUNCTION__, (void*) branch_target);
    branch_target++;

    //get patching offset for new branch
    char roothash_failed_string[sizeof("could not authenticate personalized root hash!")] = "could not authenticate personalized root hash!";

    unsigned char *roothash_failed_loc = memmem(kernel_buf, kernel_len, roothash_failed_string, sizeof("could not authenticate personalized root hash!") - 1);
    if(!roothash_failed_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, roothash_failed_string);
        return -1;
    }

    for (; *roothash_failed_loc != 0; roothash_failed_loc--);
    roothash_failed_loc++;
    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, roothash_failed_string, GET_OFFSET(kernel_len, roothash_failed_loc));

    addr_t roothash_failed_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, roothash_failed_loc));
    if(!roothash_failed_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, roothash_failed_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, roothash_failed_string, (void*) roothash_failed_ref);

    addr_t patch_loc = 0;

    for (int i = 0; i < 16; i++, roothash_failed_ref -= 4) {
        if (cbz_ref64_back(kernel_buf, roothash_failed_ref, roothash_failed_ref)) {
            printf("%s: Found cbz target at %p\n", __FUNCTION__, (void*) roothash_failed_ref);
            patch_loc = roothash_failed_ref;
            break;
        }
    }

    if (!patch_loc) {
        printf("%s: Could not find cbz target\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Patching root hash check at %p\n",__FUNCTION__, (void*) patch_loc);
    *((uint32_t *) (kernel_buf + patch_loc)) = arm64_branch_instruction((uintptr_t) patch_loc, (uintptr_t) branch_target);

    return 0;
}

int get_root_volume_seal_is_broken_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    char roothash_authenticated_string[sizeof("\"root volume seal is broken %p\\n\"")] = "\"root volume seal is broken %p\\n\"";

    unsigned char *roothash_authenticated_loc = memmem(kernel_buf, kernel_len, roothash_authenticated_string, sizeof("\"root volume seal is broken %p\\n\"") - 1);
    if(!roothash_authenticated_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, roothash_authenticated_string);
        return -1;
    }

    for (; *roothash_authenticated_loc != 0; roothash_authenticated_loc--);
    roothash_authenticated_loc++;

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, roothash_authenticated_string, GET_OFFSET(kernel_len, roothash_authenticated_loc));

    addr_t roothash_authenticated_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, roothash_authenticated_loc));
    if(!roothash_authenticated_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, roothash_authenticated_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, roothash_authenticated_string, (void*) roothash_authenticated_ref);

    addr_t tbnz_ref = step64_back(kernel_buf, roothash_authenticated_ref, 20 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);

    printf("%s: Patching tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    *((uint32_t *) (kernel_buf + tbnz_ref)) = 0xd503201f;
    printf("%s: Patched tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    return 0;
}

// NEW: Patch "unencrypted data volume is not allowed" @%s:%d
int get_unencrypted_data_volume_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    char unencrypted_data_volume_string[sizeof("\"unencrypted data volume is not allowed\" @%s:%d")] = "\"unencrypted data volume is not allowed\" @%s:%d";

    unsigned char *unencrypted_data_volume_loc = memmem(kernel_buf, kernel_len, unencrypted_data_volume_string, sizeof("\"unencrypted data volume is not allowed\" @%s:%d") - 1);
    if(!unencrypted_data_volume_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, unencrypted_data_volume_string);
        return -1;
    }

    for (; *unencrypted_data_volume_loc != 0; unencrypted_data_volume_loc--);
    unencrypted_data_volume_loc++;

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, unencrypted_data_volume_string, GET_OFFSET(kernel_len, unencrypted_data_volume_loc));

    addr_t unencrypted_data_volume_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, unencrypted_data_volume_loc));
    if(!unencrypted_data_volume_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, unencrypted_data_volume_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, unencrypted_data_volume_string, (void*) unencrypted_data_volume_ref);

    addr_t tbnz_ref = step64_back(kernel_buf, unencrypted_data_volume_ref, 20 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);

    printf("%s: Patching tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    *((uint32_t *) (kernel_buf + tbnz_ref)) = 0xd503201f;
    printf("%s: Patched tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    return 0;
}

int get_update_rootfs_rw_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    char update_rootfs_rw_string[sizeof("%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all")] = "%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all";
    unsigned char *update_rootfs_rw_loc = memmem(kernel_buf, kernel_len, update_rootfs_rw_string, sizeof("%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all") - 1);
    
    if(!update_rootfs_rw_loc) {
        
        char update_rootfs_rw_string[sizeof("%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all")] = "%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all";
        unsigned char *update_rootfs_rw_loc = memmem(kernel_buf, kernel_len, update_rootfs_rw_string, sizeof("%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all") - 1);
        if (!update_rootfs_rw_loc)
        {
            printf("%s: Could not find \"%s\" string\n", __FUNCTION__, update_rootfs_rw_string);
            return -1;

        }
        
    }


    for (; *update_rootfs_rw_loc != 0; update_rootfs_rw_loc--);
    update_rootfs_rw_loc++;

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, update_rootfs_rw_string, GET_OFFSET(kernel_len, update_rootfs_rw_loc));

    addr_t update_rootfs_rw_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, update_rootfs_rw_loc));
    if(!update_rootfs_rw_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, update_rootfs_rw_string);
        return -1;
    }

    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, update_rootfs_rw_string, (void*) update_rootfs_rw_ref);

    addr_t tbnz_ref = step64_back(kernel_buf, update_rootfs_rw_ref, 200 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);

    addr_t tbnz_ref2 = step64_back(kernel_buf, tbnz_ref - 4, 200 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref2) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref2);

    printf("%s: Patching tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref2);
    *((uint32_t *) (kernel_buf + tbnz_ref2)) = 0xd503201f;
    printf("%s: Patched tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref2);

    return 0;
}

int get_amfi_out_of_my_way_patch(void* kernel_buf,size_t kernel_len) {
    
    printf("%s: Entering ...\n",__FUNCTION__);
    
    void* xnu = memmem(kernel_buf,kernel_len,"root:xnu-",9);
    int kernel_vers = atoi(xnu+9);
    printf("%s: Kernel-%d inputted\n",__FUNCTION__, kernel_vers);
    char amfiString[33] = "entitlements too small";
    int stringLen = 22;
    if (kernel_vers >= 7938) { // Using "entitlements too small" fails on iOS 15 Kernels
        strncpy(amfiString, "Internal Error: No cdhash found.", 33);
        stringLen = 32;
    }
    void* ent_loc = memmem(kernel_buf,kernel_len,amfiString,stringLen);
    if(!ent_loc) {
        printf("%s: Could not find %s string\n",__FUNCTION__, amfiString);
        return -1;
    }
    printf("%s: Found %s str loc at %p\n",__FUNCTION__,amfiString,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find %s xref\n",__FUNCTION__,amfiString);
        return -1;
    }
    printf("%s: Found %s str ref at %p\n",__FUNCTION__,amfiString,(void*)ent_ref);
    addr_t next_bl = step64(kernel_buf, ent_ref, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    if(kernel_vers>3789) { 
        next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }
    addr_t function = follow_call64(kernel_buf, next_bl);
    if(!function) {
        printf("%s: Could not find function bl\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching AMFI at %p\n",__FUNCTION__,(void*)function);
    *(uint32_t *)(kernel_buf + function) = 0x320003E0;
    *(uint32_t *)(kernel_buf + function + 0x4) = 0xD65F03C0;
    return 0;
}

int is_root_hash_authentication_required_ios_patch(void* kernel_buf,size_t kernel_len) {
    char authentication_required_string[sizeof("is_root_hash_authentication_required_ios")] = "is_root_hash_authentication_required_ios";

    unsigned char *authentication_required_loc = memmem(kernel_buf, kernel_len, authentication_required_string, sizeof("is_root_hash_authentication_required_ios") - 1);

    if(!authentication_required_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, authentication_required_string);
        return -1;
    }

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, authentication_required_string, GET_OFFSET(kernel_len, authentication_required_loc));

    addr_t authentication_required_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, authentication_required_loc));
    
    if(!authentication_required_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, authentication_required_string);
        return -1;
    }

    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, authentication_required_string, (void*) authentication_required_ref);
    addr_t function = bof64(kernel_buf, 0, authentication_required_ref);
    
    printf("%s: Patching is_root_hash_authentication_required_ios at %p\n",__FUNCTION__,(void*)function);
    
    *(uint32_t *)(kernel_buf + function) = 0xD2800000;
    *(uint32_t *)(kernel_buf + function + 0x4) = 0xD65F03C0;
    return 0;
}

int launchd_path_patch(void* kernel_buf,size_t kernel_len) {

    char launchd_path_string[sizeof("/sbin/launchd")] = "/sbin/launchd";

    unsigned char *launchd_path_loc = memmem(kernel_buf, kernel_len, launchd_path_string, sizeof("/sbin/launchd") - 1);

    if(!launchd_path_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, launchd_path_string);
        return -1;
    }

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, launchd_path_string, GET_OFFSET(kernel_len, launchd_path_loc));

    addr_t addr = (addr_t)GET_OFFSET(kernel_len, launchd_path_loc);

    printf("%s: Patching launchd at %p\n",__FUNCTION__,(void*)addr);

    *(uint32_t *)(launchd_path_loc) = 0x69626A2F;
    *(uint32_t *)(launchd_path_loc + 0x4) = 0x616C2F6E;
    *(uint32_t *)(launchd_path_loc + 0x8) = 0x68636E75;
    *(uint32_t *)(launchd_path_loc + 0x12) = 0x64;
    return 0;
}

int tfp0_patch(void* kernel_buf,size_t kernel_len) {

    char pineapple_pizza_string[sizeof("Just like pineapple on pizza, this task/thread port doesn't belong here.")] = "Just like pineapple on pizza, this task/thread port doesn't belong here.";

    unsigned char *pineapple_pizza_loc = memmem(kernel_buf, kernel_len, pineapple_pizza_string, sizeof("Just like pineapple on pizza, this task/thread port doesn't belong here.") - 1);

    if(!pineapple_pizza_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, pineapple_pizza_string);
        return -1;
    }

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, pineapple_pizza_string, GET_OFFSET(kernel_len, pineapple_pizza_loc));

    addr_t pineapple_pizza_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, pineapple_pizza_loc));
    
    if(!pineapple_pizza_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, pineapple_pizza_string);
        return -1;
    }
    
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, pineapple_pizza_string, (void*) pineapple_pizza_ref);
    
    addr_t beq = step64(kernel_buf, pineapple_pizza_ref, 100, INSN_BEQ);
    
    if(!beq) {
        printf("%s: Could not find b.eq\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found b.eq at %p\n",__FUNCTION__, (void*) beq);
    
    addr_t caller_equals_victim = beq - 0x4;
    
    printf("%s: Patching tfp0 at %p\n",__FUNCTION__,(void*)caller_equals_victim);
    
    *(uint32_t *)(kernel_buf + caller_equals_victim) = 0xEB1F03FF;
    return 0;
};

int force_developer_mode(void* kernel_buf,size_t kernel_len) {
    char devmode_status_string[sizeof("AMFI: trying to get developer mode status from ACM\n")] = "AMFI: trying to get developer mode status from ACM\n";
    
    unsigned char *devmode_status_loc = memmem(kernel_buf, kernel_len, devmode_status_string, sizeof("AMFI: trying to get developer mode status from ACM\n") - 1);
    
    if(!devmode_status_loc) {
        printf("%s: Could not find \"AMFI: trying to get developer mode status from ACM\"\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found \"AMFI: trying to get developer mode status from ACM\" str loc at %p\n",__FUNCTION__, (void*) GET_OFFSET(kernel_len, devmode_status_loc));
    
    addr_t devmode_status_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, devmode_status_loc));
    
    if(!devmode_status_ref) {
        printf("%s: Could not find \"AMFI: trying to get developer mode status from ACM\" xref\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found \"AMFI: trying to get developer mode status from ACM\" xref at %p\n",__FUNCTION__, (void*) devmode_status_ref);
    
    addr_t cbz = step64_back(kernel_buf, devmode_status_ref, 100, INSN_CBZ);
    
    if(!cbz) {
        printf("%s: Could not find cbz\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Patching developer mode at %p\n",__FUNCTION__,(void*)cbz);
    
    *(uint32_t *)(kernel_buf + cbz) = 0x14000000 + ((*(uint32_t *)(kernel_buf + cbz) & 0x03ffffff) >> 5); // force branching
    
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Version: MOD edwin ;]" "\n");
        printf("Usage: %s <kernel_in> <kernel_out> <args>\n",argv[0]);
        printf("\t-a\t\tPatch AMFI\n");
        printf("\t-f\t\tPatch AppleFirmwareUpdate img4 signature check\n");
        printf("\t-s\t\tPatch SPUFirmwareValidation (iOS 15 Only)\n");
        printf("\t-b\t\tBypassFirmwareValidate (IOS14 TESTED), add -b13 -b15 if you want to path ios 13, 15\n");
        printf("\t-r\t\tPatch RootVPNotAuthenticatedAfterMounting (iOS 15 Only)\n");
        printf("\t-w\t\tPatch image4 grafting+trustcache load cryptex1 (iOS 16+ Only)\n");
        printf("\t-o\t\tPatch could_not_authenticate_personalized_root_hash (iOS 15 Only)\n");
        printf("\t-e\t\tPatch root volume seal is broken (iOS 15 Only)\n");
        printf("\t-u\t\tPatch update_rootfs_rw (iOS 15 Only)\n");
        printf("\t-ue\t\tPatch unencrypted data volume is not allowed (iOS 15 Only)\n");
        printf("\t-p\t\tPatch AMFIInitializeLocalSigningPublicKey (iOS 15 Only)\n");
        printf("\t-h\t\tPatch is_root_hash_authentication_required_ios (iOS 16 only)\n");
        printf("\t-l\t\tPatch launchd path\n");
        //printf("\t-t\t\tPatch tfp0\n");
        printf("\t-d\t\tPatch developer mode\n"); 
        //printf("\t-k\t\tPatch fuckthesep, based on seprmvr\n");
        printf("\t-g\t\tPatch to Disable snapshots\n");
        printf("\t-n\t\tPatch to disable touchIdSensor\n");
        printf("\t-c\t\tPatch to Disable ASLR\n");
        printf("\t-t\t\tPatch to Disable Debugger Detection by patching Ptrace\n");

        return 0;
    }
    
    void* kernel_buf;
    size_t kernel_len;
    
    fp = fopen(argv[1], "rb");
    if(!fp) {
        printf("%s: Error opening %s!\n", __FUNCTION__, argv[1]);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    kernel_buf = (void*)malloc(kernel_len);

    if(!kernel_buf) {
        printf("%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);
    
    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        printf("%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        printf("%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
    }
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-a") == 0) {
            printf("Kernel: Adding AMFI_get_out_of_my_way patch...\n");
            get_amfi_out_of_my_way_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-f") == 0) {
            printf("Kernel: Adding AppleFirmwareUpdate img4 signature check patch...\n");
            get_AppleFirmwareUpdate_img4_signature_check(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-s") == 0) {
            printf("Kernel: Adding SPUFirmwareValidation patch...\n");
            get_SPUFirmwareValidation_patch(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-b") == 0) {
            printf("Kernel: Adding tbypassFirmwareValidate patch...\n");
            bypassFirmwareValidate(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-b13") == 0) {
            printf("Kernel: Adding tbypassFirmwareValidate patch...\n");
            bypassFirmwareValidate13(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-b15") == 0) {
            printf("Kernel: Adding tbypassFirmwareValidate patch...\n");
            bypassFirmwareValidate15(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-p") == 0) {
            printf("Kernel: Adding AMFIInitializeLocalSigningPublicKey patch...\n");
            get_AMFIInitializeLocalSigningPublicKey_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-r") == 0) {
            printf("Kernel: Adding RootVPNotAuthenticatedAfterMounting patch...\n");
            get_RootVPNotAuthenticatedAfterMounting_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-w") == 0) {
            printf("Kernel: Adding image4 grafting+trustcache load cryptex1 patch...\n");
            cryptex_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-o") == 0) {
            printf("Kernel: Adding could_not_authenticate_personalized_root_hash patch...\n");
            get_could_not_authenticate_personalized_root_hash_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-e") == 0) {
            printf("Kernel: Adding root volume seal is broken patch...\n");
            get_root_volume_seal_is_broken_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-u") == 0) {
            printf("Kernel: Adding update_rootfs_rw patch...\n");
            get_update_rootfs_rw_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-ue") == 0) {
            printf("Kernel: Adding unencrypted data volume patch...\n");
            get_unencrypted_data_volume_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-h") == 0) {
            printf("Kernel: Adding is_root_hash_authentication_required_ios patch...\n");
            is_root_hash_authentication_required_ios_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-l") == 0) {
            printf("Kernel: Adding launchd patch...\n");
            launchd_path_patch(kernel_buf,kernel_len);
        }/*
        if(strcmp(argv[i], "-t") == 0) {
            printf("Kernel: Adding tfp0 patch...\n");
            tfp0_patch(kernel_buf,kernel_len);
        }*/
         if(strcmp(argv[i], "-d") == 0) {
            printf("Kernel: Adding force developer mode patch...\n");
            force_developer_mode(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-k") == 0) {
            printf("Kernel: SEP patcher...\n");
            fuck_the_sep(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-n") == 0) {
            printf("Kernel: touch id patcher...\n");
            disableTouchidSensor(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-c") == 0) {
            printf("Kernel: Adding ASLR patch...\n");
            pathAslr(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-t") == 0) {
            printf("Kernel: Adding ptrace Debugger Detection patch...\n");
            pathPtrace(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-v") == 0) {
            printf("Kernel: Adding panic007 patch...\n");
            panic007Path(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-g") == 0) {
            printf("Kernel: Adding snapshot patch patch...\n");
            pathSnapshot(kernel_buf,kernel_len);
        }
    }
    
    /* Write patched kernel */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        free(kernel_buf);
        return -1;
    }
    
    fwrite(kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);
    
    free(kernel_buf);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}
