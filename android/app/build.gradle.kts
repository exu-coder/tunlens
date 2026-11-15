plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.tunlens"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.tunlens"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // libtunlens.so is produced by `cargo ndk` (see build-native.sh) and lands
    // in src/main/jniLibs/<abi>/. No external Kotlin or AndroidX dependencies:
    // everything here is framework API.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")
}

// Convenience task: `./gradlew nativeRelease` shells out to the Rust build.
// It is intentionally not wired into `preBuild`, so a plain Kotlin build still
// works on a machine without the Rust toolchain.
tasks.register<Exec>("nativeRelease") {
    workingDir = file("../rust")
    commandLine("cargo", "ndk", "-t", "arm64-v8a", "-t", "armeabi-v7a",
        "-o", "../android/app/src/main/jniLibs", "build", "--release")
}
