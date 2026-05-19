CC64 = aarch64-linux-gnu-gcc
CC32 = aarch-linux-gnueabihf-gcc
CFLAGS = -O3 -flto -g -fno-stack-protector -ffunction-sections -fdata-sections
LDFLAGS = -Wl,--gc-sections -no-pie -lpthread
THUMB_FLAGS = #-mthumb
ALL = target_aarch64 target_hardened target_thumb target_race

all: $(ALL)

target_aarch64: target.c
	$(CC64) $(CFLAGS) $(LDFLAGS) -mbranch-protection=none $< -o $@

target_hardened: target.c
	$(CC64) $(CFLAGS) $(LDFLAGS) -mbranch-protection=standard $< -o $@


target_race: race_target.c
	$(CC64) $(CFLAGS) -mbranch-protection=standard -lpthread $< -o $@

target_thumb: target.c
	$(CC64) $(CFLAGS) $(LDFLAGS) $(THUMB_FLAGS)  $< -o $@

clean:
	rm -f $(ALL) trigger.bin assessment_report.csv exfiltration_log.txt *.dot
