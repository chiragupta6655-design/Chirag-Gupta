#!/usr/bin/env bash
#
# SecureVault launcher for macOS and Linux.
#
#   ./run.sh            build if needed, then start
#   ./run.sh rebuild    force a fresh build first
#
# First run builds the JAR, which takes a minute or two while Maven downloads
# JavaFX and Bouncy Castle. Every run after that starts straight from the JAR.

set -uo pipefail
cd "$(dirname "$0")"

JAR="target/securevault-3.0.0.jar"

printf '\n  SecureVault 3.0.0\n  -----------------\n\n'

if ! command -v java >/dev/null 2>&1; then
    printf '  [X] Java was not found on your PATH.\n\n'
    printf '      Install a JDK 17 or newer and try again.\n'
    printf '      Temurin builds: https://adoptium.net\n\n'
    exit 1
fi

if [ "${1:-}" = "rebuild" ]; then
    printf '  Rebuild requested.\n'
    rm -f "$JAR"
fi

if [ ! -f "$JAR" ]; then
    printf '  No JAR found — building. First build downloads dependencies.\n\n'
    if ! command -v mvn >/dev/null 2>&1; then
        printf '  [X] Maven was not found on your PATH, so the JAR cannot be built.\n\n'
        printf '      Install it from https://maven.apache.org/download.cgi\n\n'
        exit 1
    fi
    if ! mvn -q -DskipTests package; then
        printf '\n  [X] Build failed. Scroll up for the compiler output.\n\n'
        exit 1
    fi
    printf '  Build complete.\n\n'
fi

printf '  Starting SecureVault...\n'
printf '  Data folder: %s/SecureStorageData\n\n' "$HOME"

java -Xmx2g \
     --add-opens java.base/java.lang=ALL-UNNAMED \
     --add-opens java.base/java.io=ALL-UNNAMED \
     --add-opens java.base/java.util=ALL-UNNAMED \
     -jar "$JAR"
code=$?

# A shaded JavaFX JAR can fail on some platform/JDK combinations because the
# native libraries are not where the launcher expects. The Maven plugin loads
# JavaFX as real modules, which always works if the build succeeded.
if [ $code -ne 0 ] && command -v mvn >/dev/null 2>&1; then
    printf '\n  Exit code %d — falling back to the Maven JavaFX plugin...\n\n' "$code"
    mvn -q javafx:run
    code=$?
fi

exit $code
