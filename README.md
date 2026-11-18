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

Built from tag `v0.2.0` of [genkipool/radix-connect-iroh](https://github.com/genkipool/radix-connect-iroh).
