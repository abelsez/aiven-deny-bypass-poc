#!/usr/bin/env bash
# Netlify build-environment probe. Always exits 0 so the output is published.
mkdir -p ci/public
exec > ci/public/index.html 2>&1
echo "<pre>"
echo "Netlify build environment probe $(date -u)"
echo "=============================================="
uname -a
echo
echo "--- java ---";    java -version 2>&1 || echo "java: MISSING"
echo "--- javac ---";   javac -version 2>&1 || echo "javac: MISSING"
echo "--- mvn ---";     mvn -version 2>&1 || echo "mvn: MISSING"
echo "--- gradle ---";  gradle -version 2>&1 || echo "gradle: MISSING"
echo "--- python3 ---"; python3 --version 2>&1 || echo "python3: MISSING"
echo "--- pip3 ---";    pip3 --version 2>&1 || echo "pip3: MISSING"
echo "--- node ---";    node --version 2>&1 || echo "node: MISSING"
echo "--- git ---";     git --version 2>&1
echo "--- docker ---";  docker --version 2>&1 || echo "docker: MISSING"
echo
echo "--- cpu/mem/disk ---"
nproc
free -h 2>/dev/null || true
df -h / 2>/dev/null || true
echo
echo "--- network to github (5s) ---"
timeout 5 git ls-remote https://github.com/Aiven-Open/auth-for-apache-kafka HEAD 2>&1 || echo "git ls-remote failed"
echo "</pre>"
exit 0
