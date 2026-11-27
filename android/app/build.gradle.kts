plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.legalprivacy.noise"
    compileSdk = 34
    defaultConfig {
        applicationId = "org.legalprivacy.noise"
        minSdk = 26
        targetSdk = 34
        versionCode = (System.getenv("LP_VERSION_CODE") ?: "1").toInt()
        versionName = System.getenv("LP_VERSION_NAME") ?: "0.1.0"
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")   // sideloaded builds: signed with the debug key, not published to a store
        }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    lint { abortOnError = false }
}

dependencies {
    implementation(project(":core"))
}
