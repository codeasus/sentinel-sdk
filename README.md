--------------------------------------------------------------------------------
SENTINEL SDK
--------------------------------------------------------------------------------

A runtime SDK that detects whether an app is being tampered with, debugged,
or subjected to reverse engineering.

--------------------------------------------------------------------------------
OVERVIEW
--------------------------------------------------------------------------------

Sentinel is meant to be embedded in an application and run at runtime to
help the host app notice when its environment or integrity is being
interfered with. This repository contains the SDK library itself plus a
sample application module for exercising it.

--------------------------------------------------------------------------------
REQUIREMENTS
--------------------------------------------------------------------------------

- JDK (a compatible JDK is resolved automatically via the Foojay toolchain
  resolver plugin where configured)
- Android SDK (the project resolves Android/Google artifacts from the
  google() repository)
- No manual Gradle install needed: use the included wrapper (gradlew)

Dependencies are resolved from:

- Google Maven (google())
- Maven Central (mavenCentral())


--------------------------------------------------------------------------------
GETTING STARTED
--------------------------------------------------------------------------------

1. Clone the repository

   git clone https://github.com/codeasus/sentinel-sdk.git
   cd sentinel-sdk

2. Build the whole project

   Linux / macOS:   ./gradlew build
   Windows:         gradlew.bat build

3. Build only the SDK module

   ./gradlew :sdk:sentinel:build

4. Build / install the sample app

   ./gradlew :app:assembleDebug
   ./gradlew :app:installDebug      (with a device or emulator attached)

You can also open the project in Android Studio and run the "app"
configuration directly.


--------------------------------------------------------------------------------
USING THE SDK IN YOUR OWN PROJECT
--------------------------------------------------------------------------------

Within a multi-module build, add the module as a dependency:

// settings.gradle.kts
include(":sdk:sentinel")

// your-app/build.gradle.kts
dependencies {
implementation(project(":sdk:sentinel"))
}

Initialization and API usage examples:

[TODO: Add the SDK's entry point and example calls here once the public
API is finalized.]


--------------------------------------------------------------------------------
WHAT SENTINEL IS INTENDED TO DETECT
--------------------------------------------------------------------------------

- Tampering with the application
- Debugger attachment
- Reverse-engineering activity

[TODO: List the specific checks implemented in the SDK.]


--------------------------------------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------------------------------------

Runtime detection is one layer of defense, not a guarantee. Determined
attackers can often bypass client-side checks, so combine Sentinel with
other measures (code obfuscation, server-side validation, secure storage,
etc.) rather than relying on it alone.


--------------------------------------------------------------------------------
CONTRIBUTING
--------------------------------------------------------------------------------

Issues and pull requests are welcome via GitHub:
https://github.com/codeasus/sentinel-sdk/issues


--------------------------------------------------------------------------------
LICENSE
--------------------------------------------------------------------------------

None as of this moment


--------------------------------------------------------------------------------
AUTHOR
--------------------------------------------------------------------------------

codeasus  -  https://github.com/codeasus