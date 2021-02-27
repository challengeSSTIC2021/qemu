/*
 * Levex's PCI device
 *
 * Copyright (c) 2014 Levente Kurusa <levex@linux.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "qemu/event_notifier.h"
#include "qemu/osdep.h"
#include "crypto/hash.h"
#include "qemu-common.h"
#include <time.h>
//#include <stdint.h>

//const char DEBUG_KEY[] =  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
//const char PROD_KEY[]  = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
//const char WB_MASTER_KEY[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const char WB_MASTER_KEY[] = "\xdd\x2d\xbe\x18\x99\x1c\xd1\xc3\x82\x16\xc4\xc0\x53\xa1\xdf\x0b";

const uint64_t debug_ids[] = {0x4307121376ebbe45, 0x0906271dff3e20b4, 0x7e0a6dea7841ef77, 0};
const uint64_t prod_ids[] = {0x9c92b27651376bfb, 0xd088c64e7d30e539, 0xa2faa696cc009d53, 0};

const char* debug_keys[] = {
   "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
   "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
   "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f",
   NULL
};

const char* prod_keys[] = {
   "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f",
   "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f",
   "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf",
   NULL
};

// sstic deb registers
#define STDIN_PHY_ADDR 0
#define STDOUT_PHY_ADDR 4
#define STDERR_PHY_ADDR 0x8
#define CODE_PHY_ADDR 0xc
#define STDIN_SIZE 0x10
#define STDOUT_SIZE 0x14
#define STDERR_SIZE 0x18
#define CODE_SIZE 0x1c
#define OPCODE 0x20
#define RETCODE 0x24
#define DEBUG_MODE 0x28
//thoses addr must be sequential
#define KEY0 0x30
#define KEY1 0x34
#define KEY2 0x38
#define KEY3 0x3c
#define EXEC 0x40
#define KEYID_LO 0x44
#define KEYID_HI 0x48

#define OPCODE_WB_DEC 1
#define OPCODE_EXEC_CODE 2

//#define DEBUG_SSTIC 1

//not sure why I can't use stdint
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
//uint_t wtf
typedef unsigned int uint_t;

 typedef struct
 {
    uint8_t index;
    uint8_t key;
    uint8_t shift;
    uint8_t position;
 } CamelliaSubkey;



 typedef struct
 {
    unsigned int nr;
    uint32_t k[16];
    uint32_t ks[68];
 } CamelliaContext;

typedef struct phy_buf
{
    unsigned int size;
    unsigned int phys_addr;
} phy_buf;

typedef struct sstic_command{
    unsigned int opcode;
    phy_buf code;
    phy_buf stdin;
    phy_buf stdout;
    phy_buf stderr;
    int retcode;
} sstic_command;



typedef struct SSTICDevState {
    PCIDevice parent_obj;
    MemoryRegion mmio;
    MemoryRegion portio;

    unsigned int debug_state;
    unsigned long keyid_lo;
    unsigned long keyid_hi;
    struct sstic_command command;

} SSTICDevState;





struct dec_payload
{
    uint8_t buf[16];
    unsigned long id;
};

//compiler want prototypes
int wb_generate_key(unsigned long id, uint8_t key[16]);
int wb_decrypt(uint8_t ct[16], uint8_t key[16]);
void command_decrypt_wb(struct sstic_command *command);
int camelliaInit(CamelliaContext *context, const uint8_t *key, size_t keyLen);
void camelliaDecryptBlock(CamelliaContext *context, const uint8_t *input, uint8_t *output);
void execute_command(SSTICDevState *d);
int find_idx(const unsigned long ids[], unsigned long req_id);

#define TYPE_PCI_SSTIC_DEV "pci-sstic"

#define PCI_SSTIC_DEV(obj) \
    OBJECT_CHECK(SSTICDevState, (obj), TYPE_PCI_SSTIC_DEV)

//TODO check ID
int wb_generate_key(unsigned long id, uint8_t key[16])
{
    int ret;
    Error *err = NULL;
    //could avoid the copy
    char payload[20];

    unsigned int t = time(NULL);
    if(id > t)
    {
        #ifdef DEBUG_SSTIC
        fprintf(stderr,"id is in the futur\n");
        #endif
        return -1;
    }

    memcpy(payload, WB_MASTER_KEY, 16);
    memcpy(payload+16,&id,4);
    uint8_t *result = NULL;
    size_t reslen = 0;
    ret = qcrypto_hash_bytes(QCRYPTO_HASH_ALG_SHA256, payload, 20, &result, &reslen, &err);
    if(ret)
    {
        #ifdef DEBUG_SSTIC
        fprintf(stderr,"sha256 failed : %s\n", *((char **)err));
        #endif
        return ret;
    }
    if(reslen != 32)
        return -1;
    memcpy(key, result, 16);
    #ifdef DEBUG_SSTIC
    fprintf(stderr,"generated key:\n");
    qemu_hexdump(stderr, "", key, 16);
    #endif
    g_free(result);
    return 0;
}

int wb_decrypt(uint8_t ct[16], uint8_t key[16])
{
    CamelliaContext ctxt;
    uint8_t pt[16];
    int ret;
    ret = camelliaInit(&ctxt, key, 16);
    if(ret)
        return ret;
    camelliaDecryptBlock(&ctxt,ct,pt);
    #ifdef DEBUG_SSTIC
    fprintf(stderr,"decrypt_block:\n");
    qemu_hexdump(stderr, "", pt, 16);
    #endif
    memcpy(ct,pt,16);
    return 0;
}

void command_decrypt_wb(struct sstic_command *command)
{
    struct dec_payload pay;
    uint8_t key[16];
    #ifdef DEBUG_SSTIC
    fprintf(stderr,"in decrypt\n");
    #endif

    int ret;
    if (command->stdin.size < sizeof(struct dec_payload) || !command->stdin.phys_addr)
    {
        #ifdef DEBUG_SSTIC
        fprintf(stderr,"stdin addr %x size: %x\n", command->stdin.size, command->stdin.phys_addr);
        #endif
        command->retcode = -EINVAL;
        return;
    }
    if (command->stdout.size < 16 || !command->stdout.phys_addr)
    {
        #ifdef DEBUG_SSTIC
        fprintf(stderr,"stdout addr %x size: %x\n", command->stdout.size, command->stdout.phys_addr);
        #endif
        command->retcode = -EINVAL;
        return;
    }
    cpu_physical_memory_read(command->stdin.phys_addr, (void*)&pay,sizeof(pay));
    #ifdef DEBUG_SSTIC
    fprintf(stderr,"will generate key\n");
    #endif
    ret = wb_generate_key(pay.id, key);
    if(ret == -1)
    {
        command->retcode = -EINVAL;
        return;
    }
    #ifdef DEBUG_SSTIC
    fprintf(stderr,"will decrypt\n");
    #endif
    ret = wb_decrypt(pay.buf, key);
    if(ret == -1)
    {
        command->retcode = -EINVAL;
        return;
    }
    cpu_physical_memory_write(command->stdout.phys_addr, pay.buf, 16);
    command->retcode = 0;
}

int find_idx(const unsigned long ids[], unsigned long req_id)
{
   int i;
   for(i=0; ids[i] != 0; i++)
   {
      if(ids[i] == req_id)
         return i;
   }
   return -1;
}

static uint64_t
pci_sstic_read(void *opaque, hwaddr addr, unsigned size)
{
   SSTICDevState *d = opaque;
   unsigned long id = (d->keyid_hi << 32) | d->keyid_lo;
   const char *key;
   int idx;
   if(addr % 4)
      return 0;
   if(size != 4)
      return 0;

   switch(addr) {
      case RETCODE:
         return d->command.retcode;
      case DEBUG_MODE:
         return d->debug_state;
   }

   int want_prod_key = d->keyid_hi >> 31;
   if(want_prod_key && d->debug_state)
   {
      return 0;
   }
   idx = find_idx(want_prod_key ? prod_ids : debug_ids, id);
   if(idx == -1)
      return 0;
   key = want_prod_key ? prod_keys[idx] : debug_keys[idx];

   switch(addr) {
      case KEY0:
         return *((uint32_t*)(key));
      case KEY1:
         return *((uint32_t*)(key + 4));
      case KEY2:
         return *((uint32_t*)(key + 0x8));
      case KEY3:
         return *((uint32_t*)(key + 0xc));
   }
   return 0;
}

void execute_command(SSTICDevState *d)
{
   #ifdef DEBUG_SSTIC
   fprintf(stderr,"in command\n");
   #endif

   switch(d->command.opcode)
   {
      case OPCODE_WB_DEC:
         command_decrypt_wb(&d->command);
         #ifdef DEBUG_SSTIC
         fprintf(stderr,"retcode : %d\n",d->command.retcode);
         #endif
         break;
      default:
         d->command.retcode = -EINVAL;
   }
}

static void
pci_sstic_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                       unsigned size)
{
    #ifdef DEBUG_SSTIC
    fprintf(stderr,"in write addr: %lx, val = %lx size = %x\n",addr, val, size);
    #endif

    SSTICDevState *d = opaque;
    if(addr % 4)
        return;
    if(size != 4)
        return;

    switch(addr) {
         case DEBUG_MODE:
               d->debug_state = val;
               break;
         case STDIN_PHY_ADDR:
               d->command.stdin.phys_addr = val;
               break;
         case STDOUT_PHY_ADDR:
               d->command.stdout.phys_addr = val;
               break;
         case CODE_PHY_ADDR:
               d->command.code.phys_addr = val;
               break;
         case STDERR_PHY_ADDR:
               d->command.stderr.phys_addr = val;
               break;
         case STDIN_SIZE:
               d->command.stdin.size = val;
            break;
         case STDOUT_SIZE:
               d->command.stdout.size = val;
            break;
         case STDERR_SIZE:
               d->command.stderr.size = val;
            break;
         case CODE_SIZE:
               d->command.code.size = val;
            break;
         case OPCODE:
               d->command.opcode = val;
               break;
         case EXEC:
               execute_command(d);
               break;
         case KEYID_LO:
            d->keyid_lo = val;
            break;
         case KEYID_HI:
            d->keyid_hi = val;
            break;
    }

   return;
}

static const MemoryRegionOps pci_sstic_mmio_ops = {
    .read = pci_sstic_read,
    .write = pci_sstic_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void pci_sstic_realize(PCIDevice *pci_dev, Error **errp)
{
    SSTICDevState *d = PCI_SSTIC_DEV(pci_dev);
    uint8_t *pci_conf;

    pci_conf = pci_dev->config;

    pci_conf[PCI_INTERRUPT_PIN] = 0; /* no interrupt pin */

    memory_region_init_io(&d->mmio, OBJECT(d), &pci_sstic_mmio_ops, d,
                          "pci-sstic-mmio", 256);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

    memset(&d->command,0,sizeof(sstic_command));
    d->debug_state = 1;
    *errp = NULL;
/*here init for device*/
/*
    d->pos = 0;
    d->buf = g_malloc(14);
    memcpy(d->buf, "Hello, world!\n", 14);
    d->buflen = 14;
    printf("Loaded lev pci\n");*/

    //return 0;
}

static void
pci_sstic_uninit(PCIDevice *dev)
{
    //PCILevDevState *d = PCI_LEV_DEV(dev);
    //printf("unloaded lev pci\n");
}

static void qdev_pci_sstic_reset(DeviceState *dev)
{
    //PCILevDevState *d = PCI_LEV_DEV(dev);
}

static void pci_sstic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_sstic_realize;
    k->exit = pci_sstic_uninit;
    k->vendor_id = 0x1337;
    k->device_id = 0x0010;
    k->revision = 0x00;
    k->class_id = PCI_CLASS_OTHERS;
    dc->desc = "SSTIC PCI";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->reset = qdev_pci_sstic_reset;
}

static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };

static const TypeInfo pci_sstic_info = {
    .name          = TYPE_PCI_SSTIC_DEV,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(SSTICDevState),
    .class_init    = pci_sstic_class_init,
    .interfaces    = interfaces
};

static void pci_sstic_register_types(void)
{
    type_register_static(&pci_sstic_info);
}

type_init(pci_sstic_register_types)



//------------------------- camellia




#define ROL32(x,n) ( (x)<<(n) | ((x) & 0xffffffff) >> (32-(n)) )
#define ROR32(x,n) ( (x)>>(n) | ((x) & 0xffffffff) << (32-(n)) )



#ifndef arraysize
    #define arraysize(a) (sizeof(a) / sizeof(a[0]))
 #endif
#ifdef HTONS
    #undef HTONS
 #endif

 #ifdef HTONL
    #undef HTONL
 #endif

 #ifdef HTONLL
    #undef HTONLL
 #endif

 #ifdef htons
    #undef htons
 #endif

 #ifdef htonl
    #undef htonl
 #endif

 #ifdef htonll
    #undef htonll
 #endif

 #ifdef NTOHS
    #undef NTOHS
 #endif

 #ifdef NTOHL
    #undef NTOHL
 #endif

 #ifdef NTOHLL
    #undef NTOHLL
 #endif

 #ifdef ntohs
    #undef ntohs
 #endif

 #ifdef ntohl
    #undef ntohl
 #endif

 #ifdef ntohll
    #undef ntohll
 #endif

 #ifdef HTOLE16
    #undef HTOLE16
 #endif

 #ifdef HTOLE32
    #undef HTOLE32
 #endif

 #ifdef HTOLE64
    #undef HTOLE64
 #endif

 #ifdef htole16
    #undef htole16
 #endif

 #ifdef htole32
    #undef htole32
 #endif

 #ifdef htole64
    #undef htole64
 #endif

 #ifdef LETOH16
    #undef LETOH16
 #endif

 #ifdef LETOH32
    #undef LETOH32
 #endif

 #ifdef LETOH64
    #undef LETOH64
 #endif

 #ifdef letoh16
    #undef letoh16
 #endif

 #ifdef letoh32
    #undef letoh32
 #endif

 #ifdef letoh64
    #undef letoh64
 #endif

 #ifdef HTOBE16
    #undef HTOBE16
 #endif

 #ifdef HTOBE32
    #undef HTOBE32
 #endif

 #ifdef HTOBE64
    #undef HTOBE64
 #endif

 #ifdef htobe16
    #undef htobe16
 #endif

 #ifdef htobe32
    #undef htobe32
 #endif

 #ifdef htobe64
    #undef htobe64
 #endif

 #ifdef BETOH16
    #undef BETOH16
 #endif

 #ifdef BETOH32
    #undef BETOH32
 #endif

 #ifdef BETOH64
    #undef BETOH64
 #endif

 #ifdef betoh16
    #undef betoh16
 #endif

 #ifdef betoh32
    #undef betoh32
 #endif

 #ifdef betoh64
    #undef betoh64
 #endif

 //Load unaligned 16-bit integer (little-endian encoding)
 #define LOAD16LE(p) ( \
    ((uint16_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint16_t)(((uint8_t *)(p))[1]) << 8))

 //Load unaligned 16-bit integer (big-endian encoding)
 #define LOAD16BE(p) ( \
    ((uint16_t)(((uint8_t *)(p))[0]) << 8) | \
    ((uint16_t)(((uint8_t *)(p))[1]) << 0))

 //Load unaligned 24-bit integer (little-endian encoding)
 #define LOAD24LE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 0)| \
    ((uint32_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 16))

 //Load unaligned 24-bit integer (big-endian encoding)
 #define LOAD24BE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 16) | \
    ((uint32_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 0))

 //Load unaligned 32-bit integer (little-endian encoding)
 #define LOAD32LE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint32_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 16) | \
    ((uint32_t)(((uint8_t *)(p))[3]) << 24))

 //Load unaligned 32-bit integer (big-endian encoding)
 #define LOAD32BE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 24) | \
    ((uint32_t)(((uint8_t *)(p))[1]) << 16) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[3]) << 0))

 //Load unaligned 48-bit integer (little-endian encoding)
 #define LOAD48LE(p) ( \
    ((uint64_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint64_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint64_t)(((uint8_t *)(p))[2]) << 16) | \
    ((uint64_t)(((uint8_t *)(p))[3]) << 24) | \
    ((uint64_t)(((uint8_t *)(p))[4]) << 32) | \
    ((uint64_t)(((uint8_t *)(p))[5]) << 40))

 //Load unaligned 48-bit integer (big-endian encoding)
 #define LOAD48BE(p) ( \
    ((uint64_t)(((uint8_t *)(p))[0]) << 40) | \
    ((uint64_t)(((uint8_t *)(p))[1]) << 32) | \
    ((uint64_t)(((uint8_t *)(p))[2]) << 24) | \
    ((uint64_t)(((uint8_t *)(p))[3]) << 16) | \
    ((uint64_t)(((uint8_t *)(p))[4]) << 8) | \
    ((uint64_t)(((uint8_t *)(p))[5]) << 0))

 //Load unaligned 64-bit integer (little-endian encoding)
 #define LOAD64LE(p) ( \
    ((uint64_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint64_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint64_t)(((uint8_t *)(p))[2]) << 16) | \
    ((uint64_t)(((uint8_t *)(p))[3]) << 24) | \
    ((uint64_t)(((uint8_t *)(p))[4]) << 32) | \
    ((uint64_t)(((uint8_t *)(p))[5]) << 40) | \
    ((uint64_t)(((uint8_t *)(p))[6]) << 48) | \
    ((uint64_t)(((uint8_t *)(p))[7]) << 56))

 //Load unaligned 64-bit integer (big-endian encoding)
 #define LOAD64BE(p) ( \
    ((uint64_t)(((uint8_t *)(p))[0]) << 56) | \
    ((uint64_t)(((uint8_t *)(p))[1]) << 48) | \
    ((uint64_t)(((uint8_t *)(p))[2]) << 40) | \
    ((uint64_t)(((uint8_t *)(p))[3]) << 32) | \
    ((uint64_t)(((uint8_t *)(p))[4]) << 24) | \
    ((uint64_t)(((uint8_t *)(p))[5]) << 16) | \
    ((uint64_t)(((uint8_t *)(p))[6]) << 8) | \
    ((uint64_t)(((uint8_t *)(p))[7]) << 0))

 //Store unaligned 16-bit integer (little-endian encoding)
 #define STORE16LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint16_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint16_t)(a) >> 8) & 0xFFU

 //Store unaligned 32-bit integer (big-endian encoding)
 #define STORE16BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint16_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint16_t)(a) >> 0) & 0xFFU

 //Store unaligned 24-bit integer (little-endian encoding)
 #define STORE24LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 16) & 0xFFU

 //Store unaligned 24-bit integer (big-endian encoding)
 #define STORE24BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 0) & 0xFFU

 //Store unaligned 32-bit integer (little-endian encoding)
 #define STORE32LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint32_t)(a) >> 24) & 0xFFU

 //Store unaligned 32-bit integer (big-endian encoding)
 #define STORE32BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint32_t)(a) >> 0) & 0xFFU

 //Store unaligned 48-bit integer (little-endian encoding)
 #define STORE48LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 32) & 0xFFU, \
    ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 40) & 0xFFU,

 //Store unaligned 48-bit integer (big-endian encoding)
 #define STORE48BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 40) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 32) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 0) & 0xFFU

 //Store unaligned 64-bit integer (little-endian encoding)
 #define STORE64LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 32) & 0xFFU, \
    ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 40) & 0xFFU, \
    ((uint8_t *)(p))[6] = ((uint64_t)(a) >> 48) & 0xFFU, \
    ((uint8_t *)(p))[7] = ((uint64_t)(a) >> 56) & 0xFFU

 //Store unaligned 64-bit integer (big-endian encoding)
 #define STORE64BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 56) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 48) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 40) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 32) & 0xFFU, \
    ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[6] = ((uint64_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[7] = ((uint64_t)(a) >> 0) & 0xFFU

 //Swap a 16-bit integer
 #define SWAPINT16(x) ( \
    (((uint16_t)(x) & 0x00FFU) << 8) | \
    (((uint16_t)(x) & 0xFF00U) >> 8))

 //Swap a 32-bit integer
 #define SWAPINT32(x) ( \
    (((uint32_t)(x) & 0x000000FFUL) << 24) | \
    (((uint32_t)(x) & 0x0000FF00UL) << 8) | \
    (((uint32_t)(x) & 0x00FF0000UL) >> 8) | \
    (((uint32_t)(x) & 0xFF000000UL) >> 24))

 //Swap a 64-bit integer
 #define SWAPINT64(x) ( \
    (((uint64_t)(x) & 0x00000000000000FFULL) << 56) | \
    (((uint64_t)(x) & 0x000000000000FF00ULL) << 40) | \
    (((uint64_t)(x) & 0x0000000000FF0000ULL) << 24) | \
    (((uint64_t)(x) & 0x00000000FF000000ULL) << 8) | \
    (((uint64_t)(x) & 0x000000FF00000000ULL) >> 8) | \
    (((uint64_t)(x) & 0x0000FF0000000000ULL) >> 24) | \
    (((uint64_t)(x) & 0x00FF000000000000ULL) >> 40) | \
    (((uint64_t)(x) & 0xFF00000000000000ULL) >> 56))



 //Little-endian machine?


 //Host byte order to network byte order
 #define HTONS(value) SWAPINT16(value)
 #define HTONL(value) SWAPINT32(value)
 #define HTONLL(value) SWAPINT64(value)
 #define htons(value) swapInt16((uint16_t) (value))
 #define htonl(value) swapInt32((uint32_t) (value))
 #define htonll(value) swapInt64((uint64_t) (value))

 //Network byte order to host byte order
 #define NTOHS(value) SWAPINT16(value)
 #define NTOHL(value) SWAPINT32(value)
 #define NTOHLL(value) SWAPINT64(value)
 #define ntohs(value) swapInt16((uint16_t) (value))
 #define ntohl(value) swapInt32((uint32_t) (value))
 #define ntohll(value) swapInt64((uint64_t) (value))

 //Host byte order to little-endian byte order
 #define HTOLE16(value) (value)
 #define HTOLE32(value) (value)
 #define HTOLE64(value) (value)
 #define htole16(value) ((uint16_t) (value))
 #define htole32(value) ((uint32_t) (value))
 #define htole64(value) ((uint64_t) (value))

 //Little-endian byte order to host byte order
 #define LETOH16(value) (value)
 #define LETOH32(value) (value)
 #define LETOH64(value) (value)
 #define letoh16(value) ((uint16_t) (value))
 #define letoh32(value) ((uint32_t) (value))
 #define letoh64(value) ((uint64_t) (value))

 //Host byte order to big-endian byte order
 #define HTOBE16(value) SWAPINT16(value)
 #define HTOBE32(value) SWAPINT32(value)
 #define HTOBE64(value) SWAPINT64(value)


 //Big-endian byte order to host byte order
 #define BETOH16(value) SWAPINT16(value)
 #define BETOH32(value) SWAPINT32(value)
 #define BETOH64(value) SWAPINT64(value)






 //Camellia round function
 #define CAMELLIA_ROUND(left1, left2, right1, right2, k1, k2) \
 { \
    temp1 = left1 ^ k1; \
    temp2 = left2 ^ k2; \
    CAMELLIA_S(temp1, temp2); \
    CAMELLIA_P(temp1, temp2); \
    temp1 ^= right2; \
    temp2 ^= right1; \
    right1 = left1; \
    right2 = left2; \
    left1 = temp2; \
    left2 = temp1; \
 }

 //F-function
 #define CAMELLIA_F(xl, xr, kl, kr) \
 { \
    xl = xl ^ kl; \
    xl = xr ^ kr; \
    CAMELLIA_S(xl, xr); \
    CAMELLIA_P(xl, xr); \
 }

 //FL-function
 #define CAMELLIA_FL(xl, xr, kl, kr) \
 { \
    temp1 = (xl & kl); \
    xr ^= ROL32(temp1, 1); \
    xl ^= (xr | kr); \
 }

 //Inverse FL-function
 #define CAMELLIA_INV_FL(yl, yr, kl, kr) \
 { \
    yl ^= (yr | kr); \
    temp1 = (yl & kl); \
    yr ^= ROL32(temp1, 1); \
 }

 //S-function
 #define CAMELLIA_S(zl, zr) \
 { \
    zl = (sbox1[(zl >> 24) & 0xFF] << 24) | (sbox2[(zl >> 16) & 0xFF] << 16) | \
       (sbox3[(zl >> 8) & 0xFF] << 8) | sbox4[zl & 0xFF]; \
    zr = (sbox2[(zr >> 24) & 0xFF] << 24) | (sbox3[(zr >> 16) & 0xFF] << 16) | \
       (sbox4[(zr >> 8) & 0xFF] << 8) | sbox1[zr & 0xFF]; \
 }

 //P-function
 #define CAMELLIA_P(zl, zr) \
 { \
    zl ^= ROL32(zr, 8); \
    zr ^= ROL32(zl, 16); \
    zl ^= ROR32(zr, 8); \
    zr ^= ROR32(zl, 8); \
 }

 //Key schedule related constants
 #define KL 0
 #define KR 4
 #define KA 8
 #define KB 12
 #define L  0
 #define R  64

 //Key schedule for 128-bit key
 static const CamelliaSubkey ks1[] =
 {
    {0,  KL, 0,  L},  //kw1
    {2,  KL, 0,  R},  //kw2
    {4,  KA, 0,  L},  //k1
    {6,  KA, 0,  R},  //k2
    {8,  KL, 15, L},  //k3
    {10, KL, 15, R},  //k4
    {12, KA, 15, L},  //k5
    {14, KA, 15, R},  //k6
    {16, KA, 30, L},  //ke1
    {18, KA, 30, R},  //ke2
    {20, KL, 45, L},  //k7
    {22, KL, 45, R},  //k8
    {24, KA, 45, L},  //k9
    {26, KL, 60, R},  //k10
    {28, KA, 60, L},  //k11
    {30, KA, 60, R},  //k12
    {32, KL, 77, L},  //ke3
    {34, KL, 77, R},  //ke4
    {36, KL, 94, L},  //k13
    {38, KL, 94, R},  //k14
    {40, KA, 94, L},  //k15
    {42, KA, 94, R},  //k16
    {44, KL, 111, L}, //k17
    {46, KL, 111, R}, //k18
    {48, KA, 111, L}, //kw3
    {50, KA, 111, R}, //kw4
 };

 //Key schedule for 192 and 256-bit keys
 static const CamelliaSubkey ks2[] =
 {
    {0,  KL, 0,  L},  //kw1
    {2,  KL, 0,  R},  //k2
    {4,  KB, 0,  L},  //k1
    {6,  KB, 0,  R},  //k2
    {8,  KR, 15, L},  //k3
    {10, KR, 15, R},  //k4
    {12, KA, 15, L},  //k5
    {14, KA, 15, R},  //k6
    {16, KR, 30, L},  //ke1
    {18, KR, 30, R},  //ke2
    {20, KB, 30, L},  //k7
    {22, KB, 30, R},  //k8
    {24, KL, 45, L},  //k9
    {26, KL, 45, R},  //k10
    {28, KA, 45, L},  //k11
    {30, KA, 45, R},  //k12
    {32, KL, 60, L},  //ke3
    {34, KL, 60, R},  //ke4
    {36, KR, 60, L},  //k13
    {38, KR, 60, R},  //k14
    {40, KB, 60, L},  //k15
    {42, KB, 60, R},  //k16
    {44, KL, 77, L},  //k17
    {46, KL, 77, R},  //k18
    {48, KA, 77, L},  //ke5
    {50, KA, 77, R},  //ke6
    {52, KR, 94, L},  //k19
    {54, KR, 94, R},  //k20
    {56, KA, 94, L},  //k21
    {58, KA, 94, R},  //k22
    {60, KL, 111, L}, //k23
    {62, KL, 111, R}, //k24
    {64, KB, 111, L}, //kw3
    {66, KB, 111, R}, //kw4
 };

 //Key schedule constants
 static const uint32_t sigma[12] =
 {
    0xA09E667F, 0x3BCC908B,
    0xB67AE858, 0x4CAA73B2,
    0xC6EF372F, 0xE94F82BE,
    0x54FF53A5, 0xF1D36F1C,
    0x10E527FA, 0xDE682D1D,
    0xB05688C2, 0xB3E6C1FD
 };

 //Substitution table 1
 static const uint8_t sbox1[256] =
 {
    0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41,
    0x23, 0xEF, 0x6B, 0x93, 0x45, 0x19, 0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E, 0x1D, 0x65, 0x92, 0xBD,
    0x86, 0xB8, 0xAF, 0x8F, 0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30, 0xDC, 0x5F, 0x5E, 0xC5, 0x0B, 0x1A,
    0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47, 0x5D, 0x3D, 0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D,
    0x8B, 0x0D, 0x9A, 0x66, 0xFB, 0xCC, 0xB0, 0x2D, 0x74, 0x12, 0x2B, 0x20, 0xF0, 0xB1, 0x84, 0x99,
    0xDF, 0x4C, 0xCB, 0xC2, 0x34, 0x7E, 0x76, 0x05, 0x6D, 0xB7, 0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7,
    0x14, 0x58, 0x3A, 0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16, 0x53, 0x18, 0xF2, 0x22,
    0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24, 0x08, 0xE8, 0xA8, 0x60, 0xFC, 0x69, 0x50,
    0xAA, 0xD0, 0xA0, 0x7D, 0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95, 0xE0, 0xFF, 0x64, 0xD2,
    0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03, 0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94,
    0x87, 0x5C, 0x83, 0x02, 0xCD, 0x4A, 0x90, 0x33, 0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2,
    0x52, 0x9B, 0xD8, 0x26, 0xC8, 0x37, 0xC6, 0x3B, 0x81, 0x96, 0x6F, 0x4B, 0x13, 0xBE, 0x63, 0x2E,
    0xE9, 0x79, 0xA7, 0x8C, 0x9F, 0x6E, 0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59,
    0x78, 0x98, 0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA, 0xD4, 0x25, 0xAB, 0x42, 0x88, 0xA2, 0x8D, 0xFA,
    0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC, 0x0A, 0x36, 0x49, 0x2A, 0x68, 0x3C, 0x38, 0xF1, 0xA4,
    0x40, 0x28, 0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4, 0x77, 0xC7, 0x80, 0x9E
 };

 //Substitution table 2
 static const uint8_t sbox2[256] =
 {
    0xE0, 0x05, 0x58, 0xD9, 0x67, 0x4E, 0x81, 0xCB, 0xC9, 0x0B, 0xAE, 0x6A, 0xD5, 0x18, 0x5D, 0x82,
    0x46, 0xDF, 0xD6, 0x27, 0x8A, 0x32, 0x4B, 0x42, 0xDB, 0x1C, 0x9E, 0x9C, 0x3A, 0xCA, 0x25, 0x7B,
    0x0D, 0x71, 0x5F, 0x1F, 0xF8, 0xD7, 0x3E, 0x9D, 0x7C, 0x60, 0xB9, 0xBE, 0xBC, 0x8B, 0x16, 0x34,
    0x4D, 0xC3, 0x72, 0x95, 0xAB, 0x8E, 0xBA, 0x7A, 0xB3, 0x02, 0xB4, 0xAD, 0xA2, 0xAC, 0xD8, 0x9A,
    0x17, 0x1A, 0x35, 0xCC, 0xF7, 0x99, 0x61, 0x5A, 0xE8, 0x24, 0x56, 0x40, 0xE1, 0x63, 0x09, 0x33,
    0xBF, 0x98, 0x97, 0x85, 0x68, 0xFC, 0xEC, 0x0A, 0xDA, 0x6F, 0x53, 0x62, 0xA3, 0x2E, 0x08, 0xAF,
    0x28, 0xB0, 0x74, 0xC2, 0xBD, 0x36, 0x22, 0x38, 0x64, 0x1E, 0x39, 0x2C, 0xA6, 0x30, 0xE5, 0x44,
    0xFD, 0x88, 0x9F, 0x65, 0x87, 0x6B, 0xF4, 0x23, 0x48, 0x10, 0xD1, 0x51, 0xC0, 0xF9, 0xD2, 0xA0,
    0x55, 0xA1, 0x41, 0xFA, 0x43, 0x13, 0xC4, 0x2F, 0xA8, 0xB6, 0x3C, 0x2B, 0xC1, 0xFF, 0xC8, 0xA5,
    0x20, 0x89, 0x00, 0x90, 0x47, 0xEF, 0xEA, 0xB7, 0x15, 0x06, 0xCD, 0xB5, 0x12, 0x7E, 0xBB, 0x29,
    0x0F, 0xB8, 0x07, 0x04, 0x9B, 0x94, 0x21, 0x66, 0xE6, 0xCE, 0xED, 0xE7, 0x3B, 0xFE, 0x7F, 0xC5,
    0xA4, 0x37, 0xB1, 0x4C, 0x91, 0x6E, 0x8D, 0x76, 0x03, 0x2D, 0xDE, 0x96, 0x26, 0x7D, 0xC6, 0x5C,
    0xD3, 0xF2, 0x4F, 0x19, 0x3F, 0xDC, 0x79, 0x1D, 0x52, 0xEB, 0xF3, 0x6D, 0x5E, 0xFB, 0x69, 0xB2,
    0xF0, 0x31, 0x0C, 0xD4, 0xCF, 0x8C, 0xE2, 0x75, 0xA9, 0x4A, 0x57, 0x84, 0x11, 0x45, 0x1B, 0xF5,
    0xE4, 0x0E, 0x73, 0xAA, 0xF1, 0xDD, 0x59, 0x14, 0x6C, 0x92, 0x54, 0xD0, 0x78, 0x70, 0xE3, 0x49,
    0x80, 0x50, 0xA7, 0xF6, 0x77, 0x93, 0x86, 0x83, 0x2A, 0xC7, 0x5B, 0xE9, 0xEE, 0x8F, 0x01, 0x3D
 };

 //Substitution table 3
 static const uint8_t sbox3[256] =
 {
    0x38, 0x41, 0x16, 0x76, 0xD9, 0x93, 0x60, 0xF2, 0x72, 0xC2, 0xAB, 0x9A, 0x75, 0x06, 0x57, 0xA0,
    0x91, 0xF7, 0xB5, 0xC9, 0xA2, 0x8C, 0xD2, 0x90, 0xF6, 0x07, 0xA7, 0x27, 0x8E, 0xB2, 0x49, 0xDE,
    0x43, 0x5C, 0xD7, 0xC7, 0x3E, 0xF5, 0x8F, 0x67, 0x1F, 0x18, 0x6E, 0xAF, 0x2F, 0xE2, 0x85, 0x0D,
    0x53, 0xF0, 0x9C, 0x65, 0xEA, 0xA3, 0xAE, 0x9E, 0xEC, 0x80, 0x2D, 0x6B, 0xA8, 0x2B, 0x36, 0xA6,
    0xC5, 0x86, 0x4D, 0x33, 0xFD, 0x66, 0x58, 0x96, 0x3A, 0x09, 0x95, 0x10, 0x78, 0xD8, 0x42, 0xCC,
    0xEF, 0x26, 0xE5, 0x61, 0x1A, 0x3F, 0x3B, 0x82, 0xB6, 0xDB, 0xD4, 0x98, 0xE8, 0x8B, 0x02, 0xEB,
    0x0A, 0x2C, 0x1D, 0xB0, 0x6F, 0x8D, 0x88, 0x0E, 0x19, 0x87, 0x4E, 0x0B, 0xA9, 0x0C, 0x79, 0x11,
    0x7F, 0x22, 0xE7, 0x59, 0xE1, 0xDA, 0x3D, 0xC8, 0x12, 0x04, 0x74, 0x54, 0x30, 0x7E, 0xB4, 0x28,
    0x55, 0x68, 0x50, 0xBE, 0xD0, 0xC4, 0x31, 0xCB, 0x2A, 0xAD, 0x0F, 0xCA, 0x70, 0xFF, 0x32, 0x69,
    0x08, 0x62, 0x00, 0x24, 0xD1, 0xFB, 0xBA, 0xED, 0x45, 0x81, 0x73, 0x6D, 0x84, 0x9F, 0xEE, 0x4A,
    0xC3, 0x2E, 0xC1, 0x01, 0xE6, 0x25, 0x48, 0x99, 0xB9, 0xB3, 0x7B, 0xF9, 0xCE, 0xBF, 0xDF, 0x71,
    0x29, 0xCD, 0x6C, 0x13, 0x64, 0x9B, 0x63, 0x9D, 0xC0, 0x4B, 0xB7, 0xA5, 0x89, 0x5F, 0xB1, 0x17,
    0xF4, 0xBC, 0xD3, 0x46, 0xCF, 0x37, 0x5E, 0x47, 0x94, 0xFA, 0xFC, 0x5B, 0x97, 0xFE, 0x5A, 0xAC,
    0x3C, 0x4C, 0x03, 0x35, 0xF3, 0x23, 0xB8, 0x5D, 0x6A, 0x92, 0xD5, 0x21, 0x44, 0x51, 0xC6, 0x7D,
    0x39, 0x83, 0xDC, 0xAA, 0x7C, 0x77, 0x56, 0x05, 0x1B, 0xA4, 0x15, 0x34, 0x1E, 0x1C, 0xF8, 0x52,
    0x20, 0x14, 0xE9, 0xBD, 0xDD, 0xE4, 0xA1, 0xE0, 0x8A, 0xF1, 0xD6, 0x7A, 0xBB, 0xE3, 0x40, 0x4F
 };

 //Substitution table 4
 static const uint8_t sbox4[256] =
 {
    0x70, 0x2C, 0xB3, 0xC0, 0xE4, 0x57, 0xEA, 0xAE, 0x23, 0x6B, 0x45, 0xA5, 0xED, 0x4F, 0x1D, 0x92,
    0x86, 0xAF, 0x7C, 0x1F, 0x3E, 0xDC, 0x5E, 0x0B, 0xA6, 0x39, 0xD5, 0x5D, 0xD9, 0x5A, 0x51, 0x6C,
    0x8B, 0x9A, 0xFB, 0xB0, 0x74, 0x2B, 0xF0, 0x84, 0xDF, 0xCB, 0x34, 0x76, 0x6D, 0xA9, 0xD1, 0x04,
    0x14, 0x3A, 0xDE, 0x11, 0x32, 0x9C, 0x53, 0xF2, 0xFE, 0xCF, 0xC3, 0x7A, 0x24, 0xE8, 0x60, 0x69,
    0xAA, 0xA0, 0xA1, 0x62, 0x54, 0x1E, 0xE0, 0x64, 0x10, 0x00, 0xA3, 0x75, 0x8A, 0xE6, 0x09, 0xDD,
    0x87, 0x83, 0xCD, 0x90, 0x73, 0xF6, 0x9D, 0xBF, 0x52, 0xD8, 0xC8, 0xC6, 0x81, 0x6F, 0x13, 0x63,
    0xE9, 0xA7, 0x9F, 0xBC, 0x29, 0xF9, 0x2F, 0xB4, 0x78, 0x06, 0xE7, 0x71, 0xD4, 0xAB, 0x88, 0x8D,
    0x72, 0xB9, 0xF8, 0xAC, 0x36, 0x2A, 0x3C, 0xF1, 0x40, 0xD3, 0xBB, 0x43, 0x15, 0xAD, 0x77, 0x80,
    0x82, 0xEC, 0x27, 0xE5, 0x85, 0x35, 0x0C, 0x41, 0xEF, 0x93, 0x19, 0x21, 0x0E, 0x4E, 0x65, 0xBD,
    0xB8, 0x8F, 0xEB, 0xCE, 0x30, 0x5F, 0xC5, 0x1A, 0xE1, 0xCA, 0x47, 0x3D, 0x01, 0xD6, 0x56, 0x4D,
    0x0D, 0x66, 0xCC, 0x2D, 0x12, 0x20, 0xB1, 0x99, 0x4C, 0xC2, 0x7E, 0x05, 0xB7, 0x31, 0x17, 0xD7,
    0x58, 0x61, 0x1B, 0x1C, 0x0F, 0x16, 0x18, 0x22, 0x44, 0xB2, 0xB5, 0x91, 0x08, 0xA8, 0xFC, 0x50,
    0xD0, 0x7D, 0x89, 0x97, 0x5B, 0x95, 0xFF, 0xD2, 0xC4, 0x48, 0xF7, 0xDB, 0x03, 0xDA, 0x3F, 0x94,
    0x5C, 0x02, 0x4A, 0x33, 0x67, 0xF3, 0x7F, 0xE2, 0x9B, 0x26, 0x37, 0x3B, 0x96, 0x4B, 0xBE, 0x2E,
    0x79, 0x8C, 0x6E, 0x8E, 0xF5, 0xB6, 0xFD, 0x59, 0x98, 0x6A, 0x46, 0xBA, 0x25, 0x42, 0xA2, 0xFA,
    0x07, 0x55, 0xEE, 0x0A, 0x49, 0x68, 0x38, 0xA4, 0x28, 0x7B, 0xC9, 0xC1, 0xE3, 0xF4, 0xC7, 0x9E
 };



 int camelliaInit(CamelliaContext *context, const uint8_t *key, size_t keyLen)
 {
    uint_t i;
    uint32_t temp1;
    uint32_t temp2;
    uint32_t *k;
    const CamelliaSubkey *p;

    //Check parameters
    if(context == NULL || key == NULL)
       return -EINVAL;

    //Check the length of the key
    if(keyLen == 16)
    {
       //18 rounds are required for 128-bit key
       context->nr = 18;
    }
    else if(keyLen == 24 || keyLen == 32)
    {
       //24 rounds are required for 192 and 256-bit keys
       context->nr = 24;
    }
    else
    {
       //Report an error
       return -EINVAL;
    }

    //Point to KA, KB, KL and KR
    k = context->k;
    //Clear key contents
    memset(k, 0, 64);
    //Save the supplied secret key
    memcpy(k, key, keyLen);

    //192-bit keys require special processing
    if(keyLen == 24)
    {
       //Form a 256-bit key
       k[KR + 2] = ~k[KR + 0];
       k[KR + 3] = ~k[KR + 1];
    }

    //XOR KL and KR before applying the rounds
    for(i = 0; i < 4; i++)
    {
       k[KL + i] = BETOH32(k[KL + i]);
       k[KR + i] = BETOH32(k[KR + i]);
       k[KB + i] = k[KL + i] ^ k[KR + i];
    }

    //Generate the 128-bit keys KA and KB
    for(i = 0; i < 6; i++)
    {
       //Apply round function
       CAMELLIA_ROUND(k[KB + 0], k[KB + 1], k[KB + 2], k[KB + 3], sigma[2 * i], sigma[2 * i + 1]);

       //The 2nd round requires special processing
       if(i == 1)
       {
          //The result is XORed with KL
          k[KB + 0] ^= k[KL + 0];
          k[KB + 1] ^= k[KL + 1];
          k[KB + 2] ^= k[KL + 2];
          k[KB + 3] ^= k[KL + 3];
       }
       //The 4th round requires special processing
       else if(i == 3)
       {
          //Save KA after the 4th round
          memcpy(k + KA, k + KB, 16);
          //The result is XORed with KR
          k[KB + 0] ^= k[KR + 0];
          k[KB + 1] ^= k[KR + 1];
          k[KB + 2] ^= k[KR + 2];
          k[KB + 3] ^= k[KR + 3];
       }
    }

    //The key schedule depends on the length of key
    if(keyLen == 16)
    {
       //Key schedule for 128-bit key
       i = arraysize(ks1);
       p = ks1;
    }
    else
    {
       //Key schedule for 192 and 256-bit keys
       i = arraysize(ks2);
       p = ks2;
    }

    //Generate subkeys
    while(i > 0)
    {
       //Calculate the shift count
       uint_t n = (p->shift + p->position) / 32;
       uint_t m = (p->shift + p->position) % 32;
       //Point to KL, KR, KA or KB
       k = context->k + p->key;

       //Generate the current subkey
       if(m == 0)
       {
          context->ks[p->index] = k[n % 4];
          context->ks[p->index + 1] = k[(n + 1) % 4];
       }
       else
       {
          context->ks[p->index] = (k[n % 4] << m) | (k[(n + 1) % 4] >> (32 - m));
          context->ks[p->index + 1] = (k[(n + 1) % 4] << m) | (k[(n + 2) % 4] >> (32 - m));
       }

       //Next subkey
       p++;
       i--;
    }

    //No error to report
    return 0;
 }






 void camelliaDecryptBlock(CamelliaContext *context, const uint8_t *input, uint8_t *output)
 {
    uint_t i;
    uint32_t temp1;
    uint32_t temp2;
    uint32_t *ks;

    //The ciphertext is separated into two parts (L and R)
    uint32_t right1 = LOAD32BE(input + 0);
    uint32_t right2 = LOAD32BE(input + 4);
    uint32_t left1 = LOAD32BE(input + 8);
    uint32_t left2 = LOAD32BE(input + 12);

    //The key schedule must be applied in reverse order
    ks = (context->nr == 18) ? (context->ks + 48) : (context->ks + 64);

    //XOR ciphertext with kw3 and kw4
    right1 ^= ks[0];
    right2 ^= ks[1];
    left1 ^= ks[2];
    left2 ^= ks[3];

    //Apply round function 18 or 24 times depending on the key length
    for(i = context->nr; i > 0; i--)
    {
       //Update current location in key schedule
       ks -= 2;
       //Apply round function
       CAMELLIA_ROUND(right1, right2, left1, left2, ks[0], ks[1]);

       //6th, 12th and 18th rounds require special processing
       if(i == 7 || i == 13 || i == 19)
       {
          //Update current location in key schedule
          ks -= 4;
          //Apply FL-function
          CAMELLIA_FL(right1, right2, ks[2], ks[3])
          //Apply inverse FL-function
          CAMELLIA_INV_FL(left1, left2, ks[0], ks[1])
       }
    }

    //Update current location in key schedule
    ks -= 4;
    //XOR operation with kw1 and kw2
    left1 ^= ks[0];
    left2 ^= ks[1];
    right1 ^= ks[2];
    right2 ^= ks[3];

    //The resulting value is the plaintext
    STORE32BE(left1, output + 0);
    STORE32BE(left2, output + 4);
    STORE32BE(right1, output + 8);
    STORE32BE(right2, output + 12);
 }

