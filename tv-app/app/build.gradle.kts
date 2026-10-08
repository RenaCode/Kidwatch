plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Wersja z CI: KIDWATCH_TV_VERSION_CODE = numer przebiegu, zeby kazda
// instalacja przez ADB byla aktualizacja (versionCode musi rosnac).
val kodWersji = (System.getenv("KIDWATCH_TV_VERSION_CODE") ?: "1").toInt()

android {
    namespace = "pl.renacode.kidwatch.tv"
    compileSdk = 35

    defaultConfig {
        applicationId = "pl.renacode.kidwatch.tv"
        // Android 12 - BRAVIA XR-75X90J; MediaSessionManager i NotificationListener
        // sa starsze, ale nizej nie mamy na czym tego sprawdzic.
        minSdk = 31
        targetSdk = 35
        versionCode = kodWersji
        versionName = "0.1.$kodWersji"
    }

    signingConfigs {
        // KLUCZ DO INSTALACJI Z PLIKU (ADB), NIE DO SKLEPU. Lezy w repo celowo:
        // kazdy build z CI musi byc podpisany tym samym kluczem, inaczej
        // aktualizacja przez `pm install -r` odpada z bledem podpisu. Sklep
        // Play bedzie mial wlasny klucz (Play App Signing) - przejscie na
        // wersje ze sklepu to jednorazowe odinstalowanie tej.
        create("plik") {
            storeFile = file("../klucz-plik.jks")
            storePassword = "kidwatch-tv"
            keyAlias = "kidwatch-tv"
            keyPassword = "kidwatch-tv"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("plik")
        }
        debug {
            signingConfig = signingConfigs.getByName("plik")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}
