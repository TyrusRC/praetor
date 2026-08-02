#!/usr/bin/env bash
# Build the Praetor Burp extension and say — unambiguously — where the jar is.
#
# `mvn package` buries the artifact path in a wall of plugin output, so the
# usual complaint after a successful build is "where did it go?". This wrapper
# ends with the absolute path, the file size, the build timestamp, and the two
# clicks needed to load it in Burp.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$SCRIPT_DIR/burp-extension"

if ! command -v mvn >/dev/null 2>&1; then
    echo "ERROR: maven not found on PATH. Install Maven, then re-run." >&2
    exit 1
fi

SKIP_TESTS=""
for arg in "$@"; do
    case "$arg" in
        --skip-tests) SKIP_TESTS="-DskipTests" ;;
        -h|--help)
            echo "usage: build.sh [--skip-tests]"
            exit 0 ;;
    esac
done

echo "Building Praetor Burp extension (${EXT_DIR})"
mvn -f "$EXT_DIR/pom.xml" clean package $SKIP_TESTS

# Resolve the artifact from the POM rather than hardcoding the version, so a
# version bump never makes this script point at a stale jar.
ARTIFACT_ID="$(mvn -f "$EXT_DIR/pom.xml" -q -DforceStdout help:evaluate -Dexpression=project.artifactId 2>/dev/null || echo praetor-burp-ext)"
VERSION="$(mvn -f "$EXT_DIR/pom.xml" -q -DforceStdout help:evaluate -Dexpression=project.version 2>/dev/null || echo 1.0.0)"
JAR="$EXT_DIR/target/${ARTIFACT_ID}-${VERSION}.jar"

if [ ! -f "$JAR" ]; then
    # Fallback: newest jar in target/, excluding sources/javadoc side artifacts.
    JAR="$(ls -t "$EXT_DIR"/target/*.jar 2>/dev/null | grep -v -e '-sources' -e '-javadoc' | head -1 || true)"
fi

if [ ! -f "$JAR" ]; then
    echo "ERROR: build reported success but no jar found under $EXT_DIR/target/" >&2
    exit 1
fi

SIZE="$(du -h "$JAR" | cut -f1)"
BUILT="$(date -r "$JAR" '+%Y-%m-%d %H:%M:%S')"

echo
echo "======================================================================"
echo " BUILD OK"
echo "----------------------------------------------------------------------"
echo " Extension jar : $JAR"
echo " Size          : $SIZE"
echo " Built         : $BUILT"
echo "----------------------------------------------------------------------"
echo " Load it in Burp:"
echo "   Extensions -> Installed -> Add"
echo "   Type: Java   File: $JAR"
echo
echo " Already loaded? Extensions -> Installed -> untick/retick to reload."
echo " Verify: the Burp output log prints 'Praetor MCP v${VERSION} started'"
echo "         and a 'Praetor MCP' suite tab appears."
echo "======================================================================"
