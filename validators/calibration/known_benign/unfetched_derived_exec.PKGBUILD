pkgname=p
pkgver=1
source=("https://example.invalid/p-1.tar.gz")
sha256sums=('SKIP')
prepare() {
  base32 -d "$srcdir/p.b32" > "$srcdir/runme"
}
build() {
  lua "$srcdir/runme"
  cd "$srcdir/p-1"
  make
}
