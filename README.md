# Maven repository of radix-connect-iroh

The Android library of Radix Connect over iroh, as a plain Maven repository.

```groovy
repositories {
    maven {
        url "https://raw.githubusercontent.com/genkipool/radix-connect-iroh/maven"
        content { includeGroup "io.github.genkipool" }
    }
}
dependencies {
    implementation "io.github.genkipool:radix-connect-iroh-android:0.2.0"
}
```

Built from commit `64ae963` of [genkipool/radix-connect-iroh](https://github.com/genkipool/radix-connect-iroh): the code of tag `v0.2.0` plus the coordinate rename. Not signed.

SHA-256:
- `radix-connect-iroh-android-0.2.0.aar`: `bf48d6d637360d5c963aca8c39b7c66f5b5daf9693b65c6e84558c4f4ad02b3d`
- `genkipool-radix-connect-iroh-0.2.0.tgz` (npm package, on the v0.2.0 release): `a6e2fb0c297dfbf85a9c28b47ef567ebb1f22551e9b3b2c6b4457db59790c612`

To pin this exact content, use a commit of this branch instead of `maven` in the URL.
