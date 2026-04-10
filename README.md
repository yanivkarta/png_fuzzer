```   _   _   _   _   _   _   _   _  
 / \ / \ / \ / \ / \ / \ / \ / \ / \ 
( V | A | E | G | A | N | F | U | ZZ )
 \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ 
```

# VAEGAN Fuzzer - Part of the AI - RMF Framework. 
# This was a side project that successfully discovered serveral weaknesses and implemented full payload PoC on the weaknesses.
# integer overflow, optimization bypass(flag flipping), use-after-free and double-free were tested alongside standard overflows with advanced instrumentation techniques  purposefully to bypass existing mitigations such as PAC/BTI.
# Any viewer may be added, some viewers would require chroot/sandbox path escape for some payload. 
# Standard viewer payload is either /usr/bin/logger with a unique message or netcat 'echo ' of a message.
# Netcat logs will relatively be saved under ./logs/files/netcat/{netcat}_{id} 
# Sample images are under the 'samples' folder, view at your own risk.


This directory contains the implementation of the VAEGAN-based intelligent fuzzer for PNG images. The fuzzer leverages a Variational Autoencoder Generative Adversarial Network (VAEGAN) to generate intelligent fuzzing suggestions, aiming to discover vulnerabilities in PNG image viewers more efficiently.

## Components:

-   `ml_fuzzer_model.py`: Defines the VAEGAN architecture, training loop, and suggestion generation logic.
-   `infect_png_fuzzer.py`: The core fuzzer responsible for injecting payloads into PNGs, running viewers, monitoring for crashes, and interacting with the ML model for intelligent fuzzing.,   also trains the address oracle to overcome ASLR and other limitations.
-   `data_processor.py`: Handles the loading and processing of historical fuzzing data, including feature extraction from PNG files and crash reports, to train the VAEGAN model.
-   `crash_monitor.py`: Monitors system logs (e.g., Apport) for crash reports and parses them.
-   `png_consumer.c`: A vulnerable PNG viewer used as a target for fuzzing and for leaking addresses to aid in exploit development.
-   `png_instrumentation.so.c` : create a shared object to help with the viewer training / oracle predictions
-    `run_fuzzer_setup.py` :  prepares the environment for the fuzzing.
-    `lime_explainer.py` : create explanation diagrams on the features responsible for successful predictions by the models.
-    
## 
## Features:

-   **Intelligent Fuzzing**: Utilizes a VAEGAN model to learn from past fuzzing campaigns and generate more effective fuzzing inputs and instrumentation strategies.
-   **Advisor Mode**: Provides suggestions from the ML model without automatically applying them, allowing for manual review.
-   **Payload Injection**: Supports various fuzzing types (UAF, overflow, metadata triggers, ROP) and dynamic payload offsets.
-   **Crash Monitoring**: Integrates with GDB and Apport to detect and analyze crashes.
-   **TensorBoard Logging**: Records training progress and visualizes validated payloads for non-`png_consumer` viewers.
-   **Address Leaking**: The `png_consumer` helps in leaking internal addresses for more precise exploit development.

#pretrained models: 
- under the models folder you may find ready to use trained models for the vaegan fuzzer and the address oracle.
  

## Usage:
To setup a fuzzing environment : 



To train the VAEGAN model:
```bash
python3 infect_png_fuzzer.py --train --data_dirs fuzz_results_single
```

To run the fuzzer in intelligent mode on a single file:
```bash
python3 infect_png_fuzzer.py --single generated_image_samples/base.png --intelligent
```

To run the fuzzer in advisor mode on a directory of files:
```bash
python3 infect_png_fuzzer.py --source generated_image_samples --advisor
```

For more details on arguments, run:
```bash
python3 infect_png_fuzzer.py --help
