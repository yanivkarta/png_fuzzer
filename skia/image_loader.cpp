#include "include/core/SkData.h"
#include "include/core/SkImage.h"
#include "include/core/SkStream.h"
#include "include/core/SkBitmap.h"
#include <iostream>
#include <vector>

// Simulated Android NDK type definitions
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    int32_t  format; // e.g., WINDOW_FORMAT_RGBA_8888
} AndroidBitmapInfo;

// Emulated Android NDK Return Codes
enum {
    ANDROID_BITMAP_RESULT_SUCCESS = 0,
    ANDROID_BITMAP_RESULT_BAD_PARAMETER = -1,
    ANDROID_BITMAP_RESULT_JNI_EXCEPTION = -2,
    ANDROID_BITMAP_RESULT_ALLOCATION_FAILED = -3
};

/**
 * Simulated Android NDK function: getAndroidPixels
 * Simulates locking an Android Bitmap and copying/mapping Skia pixel contents into it.
 */
int getAndroidPixels(sk_sp<SkImage> image, AndroidBitmapInfo* outInfo, void** outPixels, std::vector<uint8_t>& pixelBuffer) {
    if (!image || !outInfo || !outPixels) {
        return ANDROID_BITMAP_RESULT_BAD_PARAMETER;
    }

    // 1. Populate Android Bitmap Information metadata structures
    outInfo->width = image->width();
    outInfo->height = image->height();
    outInfo->stride = image->width() * 4; // 4 bytes per pixel (RGBA_8888)
    outInfo->format = 1;                  // Simulated WINDOW_FORMAT_RGBA_8888

    // 2. Allocate the mock memory space that Android's VM would normally manage
    size_t totalBytes = outInfo->stride * outInfo->height;
    pixelBuffer.resize(totalBytes);
    *outPixels = pixelBuffer.data();

    // 3. Create a Skia Bitmap adapter to safely read out the image pixels
    SkBitmap bitmap;
    if (!bitmap.tryAllocN32Pixels(outInfo->width, outInfo->height)) {
        return ANDROID_BITMAP_RESULT_ALLOCATION_FAILED;
    }

    // Read pixel data out of the Skia Image wrapper into our bitmap structure
    if (!image->readPixels(bitmap.info(), bitmap.getPixels(), bitmap.rowBytes(), 0, 0)) {
        return ANDROID_BITMAP_RESULT_JNI_EXCEPTION;
    }

    // 4. Perform a direct memory copy into the locked Android pixel buffer array
    std::memcpy(*outPixels, bitmap.getPixels(), totalBytes);

    return ANDROID_BITMAP_RESULT_SUCCESS;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_image_file>\n";
        return 1;
    }

    const char* imagePath = argv[1];
    std::cout << "[Host] Opening target asset payload: " << imagePath << "\n";

    std::unique_ptr<SkFILEStream> stream = SkFILEStream::Make(imagePath);
    if (!stream) {
        std::cerr << "[Error] Failed to open target file.\n";
        return 1;
    }

    sk_sp<SkData> data = SkData::MakeFromStream(stream.get(), stream->getLength());
    if (!data) {
        std::cerr << "[Error] Failed to parse input stream context.\n";
        return 1;
    }

    sk_sp<SkImage> image = SkImages::DeferredFromEncodedData(data);
    if (!image) {
        std::cerr << "[Error] Failed to decode image file bytes.\n";
        return 1;
    }

    std::cout << "[Skia] Image successfully decoded. Size: " << image->width() << "x" << image->height() << "\n";

    // --- Start Android Simulation Hook ---
    std::cout << "\n[Android Sim] Invoking simulated getAndroidPixels() pipeline...\n";
    
    AndroidBitmapInfo info;
    void* rawPixels = nullptr;
    std::vector<uint8_t> mockAndroidMemoryHeap; // Manages the life cycle of the simulated buffer

    int result = getAndroidPixels(image, &info, &rawPixels, mockAndroidMemoryHeap);

    if (result == ANDROID_BITMAP_RESULT_SUCCESS) {
        std::cout << "[Android Sim] SUCCESS: Locked memory mapping address: " << rawPixels << "\n";
        std::cout << "[Android Sim] Bitmap Metatags -> Width: " << info.width 
                  << "px, Height: " << info.height 
                  << "px, Row Stride: " << info.stride << " bytes.\n";

        // Read a sample pixel from the raw memory pointer to verify accuracy (top-left pixel)
        uint8_t* rgba = static_cast<uint8_t*>(rawPixels);
        std::cout << "[Android Sim] Top-Left Pixel Channel Check -> "
                  << "R: " << (int)rgba[0] << " "
                  << "G: " << (int)rgba[1] << " "
                  << "B: " << (int)rgba[2] << " "
                  << "A: " << (int)rgba[3] << "\n";
    } else {
        std::cerr << "[Android Sim] ERROR: Native method call failed with code: " << result << "\n";
        return 1;
    }

    return 0;
}

