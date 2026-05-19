#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

typedef struct {
    void (*callback)();
} SecureContext;

SecureContext *global_ctx;
int stop_race = 0;

void __attribute__((used)) win_gadget() {
    printf("[!] RACE WON: PAC/BTI Bypassed via Temporal Corruption!\n");
    exit(0);
}

void safe_function() { /* Dummy safe path */ }

// Thread 1: The Victim (Dispatcher)
void* secure_dispatcher(void* arg) {
    while(!stop_race) {
        global_ctx->callback = safe_function;
        
        // --- TOCTOU WINDOW ---
        // Register-level 'LDR' and 'AUTIA' happen here in a hardened build.
        void (*local_ptr)() = global_ctx->callback;
        
        // Small delay to simulate architectural pipeline latency
        for(volatile int i=0; i<100; i++); 

        local_ptr(); // Use of the (potentially corrupted) pointer
    }
    return NULL;
}

// Thread 2: The Attacker (Corrupter)
void* attacker_thread(void* arg) {
    while(!stop_race) {
        global_ctx->callback = win_gadget;
    }
    return NULL;
}

int main() {
    global_ctx = malloc(sizeof(SecureContext));
    pthread_t t1, t2;
    printf("[*] Starting Race Condition test...\n");
    pthread_create(&t1, NULL, secure_dispatcher, NULL);
    pthread_create(&t2, NULL, attacker_thread, NULL);
    
    pthread_join(t1, NULL); 
    return 0;
}
