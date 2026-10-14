#define _GNU_SOURCE 1
#include "dt_elf.h"
#include "dt_sha256.h"
#include "dt_io.h"
#include <link.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Uses only the module containing an internal marker; no JNI address/path parameters. */
#define MAX_TEXT_BYTES (16 * 1024 * 1024)
struct search { struct dt_elf_baseline *out; size_t total; int found; };
static int discover(struct dl_phdr_info *info, size_t size, void *opaque) {
    (void)size;
    struct search *s=opaque;
    uintptr_t marker=s->out->marker;
    int contains=0;
    for (size_t i=0;i<info->dlpi_phnum;i++) {
        const ElfW(Phdr) *p=&info->dlpi_phdr[i];
        uintptr_t base=(uintptr_t)info->dlpi_addr;
        if (p->p_vaddr > UINTPTR_MAX-base) continue;
        uintptr_t address=base+(uintptr_t)p->p_vaddr;
        if (p->p_type==PT_LOAD && (p->p_flags&PF_X) && marker>=address && marker-address<p->p_memsz) contains=1;
    }
    if (!contains) return 0;
    s->found=1;
    for (size_t i=0;i<info->dlpi_phnum;i++) {
        const ElfW(Phdr) *p=&info->dlpi_phdr[i];
        if (p->p_type!=PT_LOAD || !(p->p_flags&PF_X) || !p->p_memsz) continue;
        uintptr_t base=(uintptr_t)info->dlpi_addr;
        if (!(p->p_flags&PF_R) || (p->p_flags&PF_W) ||
            p->p_vaddr>UINTPTR_MAX-base || p->p_memsz>MAX_TEXT_BYTES ||
            s->total>MAX_TEXT_BYTES-p->p_memsz || s->out->count==DT_MAX_SEGMENTS) {
            s->found=-1;return 1;
        }
        uintptr_t address=base+(uintptr_t)p->p_vaddr;
        if (p->p_memsz>UINTPTR_MAX-address) {s->found=-1;return 1;}
        struct dt_segment *segment=&s->out->segments[s->out->count++];
        segment->address=address;segment->size=(size_t)p->p_memsz;s->total+=segment->size;
    }
    return 1;
}
int dt_range_readable(const char *maps, uintptr_t start, size_t size) {
    if (!maps || !size || size>UINTPTR_MAX-start) return 0;
    uintptr_t cursor=start, end=start+size;
    const char *line=maps;
    while (*line && cursor<end) {
        unsigned long long a,b;char permissions[5]={0};
        if (sscanf(line,"%llx-%llx %4s",&a,&b,permissions)==3 &&
            a<=UINTPTR_MAX && b<=UINTPTR_MAX && a<b &&
            cursor>=(uintptr_t)a && cursor<(uintptr_t)b) {
            if (permissions[0]!='r' || permissions[1]=='w' || permissions[2]!='x') return 0;
            cursor=(uintptr_t)b<end?(uintptr_t)b:end;
        }
        const char *next=strchr(line,'\n');
        if (!next) break;
        line=next+1;
    }
    return cursor==end;
}
static char *read_maps(void) {
    size_t cap=512*1024+1, size=0;
    char *maps=malloc(cap);
    if (!maps) return NULL;
    if (dt_read("/proc/self/maps",maps,cap,&size)!=0) {free(maps);return NULL;}
    return maps;
}
int dt_elf_capture(struct dt_elf_baseline *baseline, const void *marker) {
    memset(baseline,0,sizeof(*baseline));
    baseline->marker=(uintptr_t)marker;
#if defined(__arm__)
    baseline->marker &= ~(uintptr_t)1;
#endif
    struct search s={baseline,0,0};
    dl_iterate_phdr(discover,&s);
    if (s.found!=1 || !baseline->count) return 0;
    char *maps=read_maps();
    if (!maps) return 0;
    for (size_t i=0;i<baseline->count;i++) {
        struct dt_segment *segment=&baseline->segments[i];
        if (!dt_range_readable(maps,segment->address,segment->size)) {free(maps);return 0;}
        dt_sha256((const unsigned char *)segment->address,segment->size,segment->digest);
    }
    free(maps);baseline->ready=1;return 1;
}
enum dt_state dt_elf_check(const struct dt_elf_baseline *baseline) {
    if (!baseline || !baseline->ready) return DT_UNAVAILABLE;
    struct dt_elf_baseline current={0};current.marker=baseline->marker;
    struct search s={&current,0,0};dl_iterate_phdr(discover,&s);
    if (s.found!=1 || current.count!=baseline->count) return DT_DETECTED;
    char *maps=read_maps();
    if (!maps) return DT_UNAVAILABLE;
    for (size_t i=0;i<current.count;i++) {
        const struct dt_segment *old=&baseline->segments[i], *now=&current.segments[i];
        if (old->address!=now->address || old->size!=now->size ||
            !dt_range_readable(maps,now->address,now->size)) {free(maps);return DT_DETECTED;}
        unsigned char digest[32];dt_sha256((const unsigned char *)now->address,now->size,digest);
        if (memcmp(digest,old->digest,32)!=0) {free(maps);return DT_DETECTED;}
    }
    free(maps);return DT_NOT_DETECTED;
}
