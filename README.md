# OtterCV - Otter Certificate Viewer

A JavaFX desktop application for viewing and analyzing X.509 certificates.

## Requirements

* [JDK 21+](https://www.oracle.com/java/technologies/downloads/)
* [Apache Maven 3.9.0+](https://maven.apache.org/download.cgi)
* [Inno Setup 6.2.2+](https://jrsoftware.org/isinfo.php) (for Windows native installer)

## Building

With native packages:

    mvn clean package -P native-deploy

Without native packages (ZIP only):

    mvn clean package

## Output

Cross-platform ZIP (no JRE):

    ottercv-distrib/target/ottercv-<version>-no-jre.zip

Native installers are generated in `ottercv-client/target/`.
