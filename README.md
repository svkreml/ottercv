# OtterCV - Otter Certificate Viewer

A JavaFX desktop application for viewing and analyzing X.509 certificates.

## Requirements

* [JDK 21+](https://www.oracle.com/java/technologies/downloads/)
* [Apache Maven 3.9.0+](https://maven.apache.org/download.cgi)

## Building

With native packages:

    mvn clean package -P native-deploy

Linux AppImage (standalone, no JRE bundling):

    mvn clean package -P linux-appimage

Portable Linux AppImage (works on any x86_64 Linux with GLIBC >= 2.31, requires Docker):

    ./build-appimage-docker.sh

Without native packages (ZIP only):

    mvn clean package

## Output

Cross-platform ZIP (no JRE):

    ottercv-distrib/target/ottercv-<version>-no-jre.zip

Linux AppImage:

    ottercv-client/target/ottercv-<version>-x86_64.AppImage

Native installers are generated in `ottercv-client/target/`.
