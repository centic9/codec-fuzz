This is a small project for fuzzing [Apache Commons Codec](https://commons.apache.org/proper/commons-codec/) with the [jazzer](https://github.com/CodeIntelligenceTesting/jazzer) fuzzing tool.

See [Fuzzing](https://en.wikipedia.org/wiki/Fuzzing) for a general description of the theory behind fuzzy testing.

Because Java uses a runtime environment which does not crash on invalid actions of an 
application (unless native code is invoked), Fuzzing of Java-based applications  
focuses on the following:

* verify if only expected exceptions are thrown
* verify any JNI or native code calls
* find cases of unbounded memory allocations

Apache Commons Codec does not use JNI or native code, therefore the fuzzing target mainly
tries to trigger unexpected exceptions and unbounded memory allocations.

# How to fuzz

Build the fuzzing target:

    ./gradlew shadowJar

If possible, provide a corpus of test-documents in a folder `corpus`. This improves
fuzzing a lot, both valid encoded documents and slighlty broken ones help the 
fuzzer to come up with interesting cases.

Download Jazzer from the [releases page](https://github.com/CodeIntelligenceTesting/jazzer/releases), 
choose the latest version and select the file `jazzer-<os>-<version>.tar.gz`

Unpack the archive:

    tar xzf jazzer-*.tar.gz

Create the corpus-directories

    mkdir -p corpus corpusDigest corpusLanguage

Invoke the fuzzing:

    ./jazzer --cp=build/libs/codec-fuzz-all.jar --instrumentation_includes=org.apache.commons.** --target_class=org.dstadler.codec.fuzz.Fuzz -rss_limit_mb=4096 corpus

Invoke the fuzzing for "digest" package:

    ./jazzer --cp=build/libs/codec-fuzz-all.jar --instrumentation_includes=org.apache.commons.** --target_class=org.dstadler.codec.fuzz.FuzzDigest -rss_limit_mb=4096 corpusDigest

Invoke the fuzzing for "language" package:

    ./jazzer --cp=build/libs/codec-fuzz-all.jar --instrumentation_includes=org.apache.commons.** --target_class=org.dstadler.codec.fuzz.FuzzLanguage -rss_limit_mb=4096 corpusLanguage

In this mode Jazzer will stop whenever it detects an unexpected exception 
or crashes.

You can use `--keep_going=10` to report a given number of exceptions before stopping.

See `./jazzer` for options which can control details of how Jazzer operates.

# License

Copyright 2021-2024 Dominik Stadler

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
