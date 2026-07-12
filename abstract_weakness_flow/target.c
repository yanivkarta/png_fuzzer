#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

typedef struct {
    char metadata[64];      // Padding (Offset 0x00)
    void (*callback)();    // The hijacked pointer (Offset 0x40)
} Config;

// The "Sink" - Target for the DOP attack

#ifdef __cplusplus 
extern "C" 
{
#endif __cplusplus 

void __attribute__((used)) win_gadget() {
    int ret = 0;
    printf("[!] DOP Success: Target Sink Reached.\n");
    // In a real attack, this would be a privileged operation
    ret = system("/bin/sh");

}

// Vulnerable Dispatcher: Optimized into a 'naked return' by the compiler
void __attribute__((noinline)) dispatch_callback(Config *cfg) {
    cfg->callback(); 
}
#ifdef __cplusplus

}
#endif //__cplusplus
int main(int argc, char **argv) {
    Config *cfg = malloc(sizeof(Config));
    
    // Validated Mapping Logic: Connects trigger.bin to the struct
    int fd = open("trigger.bin", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error: trigger.bin not found. Run gen_payload.py first.\n");
        return 1;
    }

    int dread = read(fd, cfg, sizeof(Config)); 
    if (dread < sizeof(Config) ) 
	    printf("[-] error read returned : %d",dread) ;

    close(fd);

    printf("[*] Struct mapped. Dispatching callback from offset 0x40...\n");
    dispatch_callback(cfg);

    free(cfg);
    return 0;
}
