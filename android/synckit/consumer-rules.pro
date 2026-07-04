# Keep kotlinx.serialization generated serializers for public envelope types.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class com.keyneom.synckit.** {
    kotlinx.serialization.KSerializer serializer(...);
}
