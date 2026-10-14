#define _GNU_SOURCE 1
#include "dt_elf.h"
#include "dt_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
extern int dt_fixture(int value);
static void vector(const char *text,const char *expected) {
    unsigned char digest[32];char actual[65];
    dt_sha256((const unsigned char *)text,strlen(text),digest);
    for(size_t i=0;i<32;i++) sprintf(actual+i*2,"%02x",digest[i]);
    assert(strcmp(actual,expected)==0);
}
int main(void) {
    vector("","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    vector("abc","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    vector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert(dt_range_readable("1000-2000 r-xp 0 0 0\n2000-3000 r-xp 0 0 0\n",0x1f00,0x200));
    assert(!dt_range_readable("1000-2000 rwxp 0 0 0\n",0x1000,16));
    assert(!dt_range_readable("1000-2000 r--p 0 0 0\n",0x1000,16));
    assert(!dt_range_readable("1000-1800 r-xp 0 0 0\n2000-3000 r-xp 0 0 0\n",0x1700,0x1000));
    struct dt_elf_baseline baseline;
    assert(dt_elf_capture(&baseline,(const void *)dt_fixture));
    assert(dt_elf_check(&baseline)==DT_NOT_DETECTED);
    /* Change one byte of our dedicated fixture library without executing it while modified. */
    uintptr_t address=(uintptr_t)dt_fixture;
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    void *start=(void *)(address & ~(uintptr_t)(page-1));
    assert(mprotect(start,page,PROT_READ|PROT_WRITE|PROT_EXEC)==0);
    assert(dt_elf_check(&baseline)==DT_DETECTED); /* permission deviation */
    volatile unsigned char *byte=(volatile unsigned char *)address;
    unsigned char saved=*byte;*byte=(unsigned char)(saved^1);
    assert(mprotect(start,page,PROT_READ|PROT_EXEC)==0);
    assert(dt_elf_check(&baseline)==DT_DETECTED); /* digest deviation beyond fixed entry probes */
    assert(mprotect(start,page,PROT_READ|PROT_WRITE|PROT_EXEC)==0);
    *byte=saved;
    assert(mprotect(start,page,PROT_READ|PROT_EXEC)==0);
    assert(dt_elf_check(&baseline)==DT_NOT_DETECTED);
    baseline.ready=0;assert(dt_elf_check(&baseline)==DT_UNAVAILABLE);
    return 0;
}
