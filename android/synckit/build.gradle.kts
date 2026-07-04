plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("maven-publish")
}

group = "com.keyneom"
version = "0.2.0-rc.0"

android {
    namespace = "com.keyneom.synckit"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("test") {
            // Repo-root fixtures/v1 — shared with the JS package.
            resources.srcDir(rootProject.projectDir.resolve("../fixtures"))
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("androidx.credentials:credentials:1.6.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.6.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}

tasks.withType<Test>().configureEach {
    // Forward parity script paths into the unit-test JVM.
    System.getenv("PARITY_OUTPUT")?.let { environment("PARITY_OUTPUT", it) }
    System.getenv("PARITY_PEER_REPORT")?.let { environment("PARITY_PEER_REPORT", it) }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.keyneom"
                artifactId = "sync-kit-android"
                version = project.version.toString()
            }
        }
        repositories {
            mavenLocal()
        }
    }
}
