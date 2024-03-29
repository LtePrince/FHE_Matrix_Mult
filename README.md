# FHE_Matrix_Mult

## The usage of the code

You can use any of the following:

### For VS

+ Copy the entire src folder into the VS project directory where the seal library is configured, and add it to the source file.
+ Change the upper-left option to Release/x64.
+ Then you can run it.

### Using CMake

Enter the project's root directory:

+ Init submodule

    ``` bash
    git submodule init && git submodule update
    ```

+ Configure project

    For example,

    ``` bash
    # Configure a release build of a static Microsoft SEAL library and also build the examples.

    cmake -S . -B build -DSEAL_BUILD_EXAMPLES=ON
    ```

    More information about SEAL's options can be found in its `README.md`.

+ Build executable
  + Build all targets

    ```bash
    cmake --build build -j
    ```

  + Build specified targets `test2`

    ```bash
    cmake --build build --target test2 -j
    ```
