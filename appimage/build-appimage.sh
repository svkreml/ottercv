#!/bin/bash
set -e

BUILD_DIR="${1:?Usage: $0 <build-dir> <appdir> <assets-dir> <jre-dir>}"
APPDIR="${2:?Usage: $0 <build-dir> <appdir> <assets-dir> <jre-dir>}"
ASSETS_DIR="${3:?Usage: $0 <build-dir> <appdir> <assets-dir> <jre-dir>}"
JRE_SRC="${4:?Usage: $0 <build-dir> <appdir> <assets-dir> <jre-dir>}"
JAR_FILE=$(find "$BUILD_DIR" -maxdepth 1 -name "*.jar" ! -name "*sources*" ! -name "*javadoc*" | head -n 1)
if [ -z "$JAR_FILE" ] || [ ! -f "$JAR_FILE" ]; then
    echo "Error: No JAR file found in $BUILD_DIR"
    exit 1
fi
LIBS_DIR="$BUILD_DIR/libs"

mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

cp "$JAR_FILE" "$APPDIR/usr/bin/"
cp -r "$LIBS_DIR"/* "$APPDIR/usr/lib/" 2>/dev/null || true

if [ -d "$JRE_SRC" ]; then
    echo "Bundling JRE from $JRE_SRC"
    mkdir -p "$APPDIR/usr/lib/jre"
    cp -r "$JRE_SRC"/* "$APPDIR/usr/lib/jre/" 2>/dev/null || true
else
    echo "Warning: JRE source directory not found: $JRE_SRC"
fi

cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
set -e

SELF=$(readlink -f "$0")
APPDIR="${SELF%/*}"
export PATH="$APPDIR/usr/bin:$PATH"
export LD_LIBRARY_PATH="$APPDIR/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

JAR=$(ls "$APPDIR/usr/bin"/*.jar 2>/dev/null | head -n 1)
if [ -z "$JAR" ]; then
    echo "Error: No JAR file found in $APPDIR/usr/bin/"
    exit 1
fi

if [ -x "$APPDIR/usr/lib/jre/bin/java" ]; then
    JAVA_CMD="$APPDIR/usr/lib/jre/bin/java"
else
    JAVA_CMD="java"
fi

exec "$JAVA_CMD" \
  -Dprism.forceGPU=true \
  --module-path "$APPDIR/usr/lib:$JAR" \
  --add-modules javafx.controls,javafx.graphics \
  -m svkreml.certificateViewer/svkreml.certificateViewer.gui.APP \
  "$@"
EOF
chmod +x "$APPDIR/AppRun"

cat > "$APPDIR/ottercv.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=OtterCV
Comment=Otter Certificate Viewer
Exec=AppRun
Icon=ottercv
Categories=Utility;Security;
EOF

cp "$ASSETS_DIR/linux/ottercv.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/ottercv.png" 2>/dev/null || true
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/ottercv.png" "$APPDIR/ottercv.png" 2>/dev/null || true
