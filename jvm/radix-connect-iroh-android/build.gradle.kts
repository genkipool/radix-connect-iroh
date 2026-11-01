plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    `maven-publish`
}

group = "com.radixdlt.connect"
version = "0.1.5"

val rustWorkspace: File = rootDir.parentFile
val generatedJniLibs = layout.buildDirectory.dir("generated/jniLibs")
val generatedKotlin = layout.buildDirectory.dir("generated/kotlin")
val androidAbis = providers.gradleProperty("radixConnectIroh.abis").get()
    .split(',').map(String::trim).filter(String::isNotEmpty)

android {
    namespace = "com.radixdlt.connect.iroh"
    compileSdk = 35

    defaultConfig {
        minSdk = 27
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets.getByName("main") {
        jniLibs.srcDir(generatedJniLibs)
        kotlin.srcDir(generatedKotlin)
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // `@aar`: the Android flavour of JNA, which ships its own native dispatch library.
    api("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
}

// Rust target triple of each Android ABI.
val abiTriples = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "armeabi-v7a" to "armv7-linux-androideabi",
    "x86_64" to "x86_64-linux-android",
    "x86" to "i686-linux-android",
)
val rustSources = fileTree(rustWorkspace.resolve("crates")) { include("**/*.rs", "**/Cargo.toml", "**/uniffi.toml") }
val rustTarget = rustWorkspace.resolve("target")

// Always the size-optimised `release-android` profile: a debug build is hundreds of MB
// per ABI and the Rust code is not debugged from Android Studio.
val cargoNdkBuild by tasks.registering(Exec::class) {
    group = "rust"
    description = "Builds libradix_connect_iroh_uniffi.so for $androidAbis with cargo-ndk."
    workingDir = rustWorkspace
    inputs.files(rustSources)
    inputs.files(rustWorkspace.resolve("Cargo.toml"), rustWorkspace.resolve("Cargo.lock"))
    inputs.property("abis", androidAbis)
    outputs.files(androidAbis.map { rustTarget.resolve("${abiTriples.getValue(it)}/release-android/libradix_connect_iroh_uniffi.so") })
    commandLine(
        buildList {
            addAll(listOf("cargo", "ndk", "--platform", "27"))
            androidAbis.forEach { addAll(listOf("-t", it)) }
            addAll(listOf("build", "--profile", "release-android", "--locked", "-p", "radix-connect-iroh-uniffi", "--lib"))
        }
    )
}

// Only our library: cargo also leaves dynamic libraries of some dependencies next to it.
val copyJniLibs by tasks.registering(Sync::class) {
    group = "rust"
    dependsOn(cargoNdkBuild)
    androidAbis.forEach { abi ->
        from(rustTarget.resolve("${abiTriples.getValue(abi)}/release-android/libradix_connect_iroh_uniffi.so")) {
            into(abi)
        }
    }
    into(generatedJniLibs)
}

// The bindings come from a host build: its uniffi metadata is the same, and it keeps the
// Android libraries free to be fully stripped.
val cargoHostBuild by tasks.registering(Exec::class) {
    group = "rust"
    workingDir = rustWorkspace
    inputs.files(rustSources)
    outputs.file(rustTarget.resolve("debug/libradix_connect_iroh_uniffi.so"))
    commandLine("cargo", "build", "--locked", "-p", "radix-connect-iroh-uniffi", "--lib")
}

val generateUniffiBindings by tasks.registering(Exec::class) {
    group = "rust"
    description = "Generates the Kotlin bindings from the library's uniffi metadata."
    dependsOn(cargoHostBuild)
    workingDir = rustWorkspace
    val library = rustTarget.resolve("debug/libradix_connect_iroh_uniffi.so")
    inputs.file(library)
    outputs.dir(generatedKotlin)
    doFirst { delete(generatedKotlin) }
    commandLine(
        "cargo", "run", "--locked", "-p", "radix-connect-iroh-uniffi", "--features", "cli",
        "--bin", "uniffi-bindgen", "--",
        "generate", "--library", library.absolutePath,
        "--language", "kotlin", "--no-format",
        "--out-dir", generatedKotlin.get().asFile.absolutePath,
    )
}

tasks.named("preBuild") { dependsOn(generateUniffiBindings, copyJniLibs) }

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "radix-connect-iroh-android"
            afterEvaluate { from(components["release"]) }
        }
    }
}
