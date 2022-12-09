plugins {
    kotlin("multiplatform") version "1.7.20"
    id("maven-publish")
}

group = "ch.oxc.nikea"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        withJava()
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
        compilations {
            val test by getting {
                tasks.withType<Test> {
                    this.testLogging {
                        this.showStandardStreams = true
                    }
                }
            }
        }
    }

    val hostOs = System.getProperty("os.name")
    val isMingwX64 = hostOs.startsWith("Windows")
    val nativeTarget = when {
        hostOs == "Mac OS X" -> macosX64("native")
        hostOs == "Linux" -> linuxX64("native")
        isMingwX64 -> mingwX64("native")
        else -> throw GradleException("Host OS is not supported in Kotlin/Native.")
    }


    sourceSets {
        val commonMain by getting {
            dependencies {
                api(kotlin("stdlib-common"))
                implementation("com.ionspin.kotlin:multiplatform-crypto-libsodium-bindings:0.8.8")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.6.4")
            }
        }
        val jvmMain by getting {
            dependencies {
                api(kotlin("stdlib"))
            }
        }
        val jvmTest by getting
        val nativeMain by getting
        val nativeTest by getting
    }
}
