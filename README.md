# OtterCV - Otter Certificate Viewer

A JavaFX desktop application for viewing and analyzing X.509 certificates.

## Requirements

* [JDK 21+](https://www.oracle.com/java/technologies/downloads/)
* [Apache Maven 3.9.0+](https://maven.apache.org/download.cgi)

## Building

Linux AppImage (standalone, no JRE bundling):

    mvn clean package -P linux-appimage

Portable Linux AppImage (works on any x86_64 Linux with GLIBC >= 2.31, requires Docker):

    ./build-appimage-docker.sh

## Creating a Release

Tag and push to trigger the GitHub Actions release workflow:

    git tag v1.1.1
    git push origin v1.1.1

## Output

Linux AppImage:

    target/ottercv-<version>-x86_64.AppImage
