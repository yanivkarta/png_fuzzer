SKIA image loader support steps :

1) clone the repo  ``` git clone https://skia.googlesource.com/skia.git ``` 
2) copy the image loader into the repo 
3) pull required dependencies,generate ninja build,build library 

``` 
python3 tools/git-sync-deps

bin/gn gen out/Release --args='is_official_build=true target_cpu="arm64" skia_use_gl=true skia_use_vulkan=false'

ninja -C out/Release skia
``` 

4) open the BUILD.gn and append : 
```
executable("image_loader") {
  sources = [ "loader.cpp" ]
  deps = [
    ":skia",
  ]
}
```
5) map and build using ninja:
```
bin/gn gen out/Release --args='is_official_build=true target_cpu="arm64" skia_use_gl=true skia_use_egl=true skia_use_system_freetype=false skia_use_system_libjpeg_turbo=false skia_use_system_libpng=false skia_use_system_zlib=false'

ninja -C out/Release image_loader
```

6) copy the image_loader executable from out/Release into the working directory of the fuzzer. 

Using the image_loader validates skia's behavior and simulates getAndroidPixels() JNI, there might be structural diffrerences and configuration differences, if the purpose is to fit to a specific android build, the configuration parameters must be mimicked in the build.
