pkgname=p
pkgver=1
build() {
  curl -fsSL https://example.invalid/data.json -o "$srcdir/data.json"
  jq -r .version "$srcdir/data.json"
}
