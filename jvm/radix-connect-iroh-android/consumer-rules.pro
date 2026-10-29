# The uniffi bindings are called through JNA, which finds classes, methods and fields
# by name at runtime: keep them and JNA itself intact.
-keep class com.radixdlt.connect.iroh.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-dontwarn java.awt.**
