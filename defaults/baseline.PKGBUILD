# Baseline recipe: recipe-mode inputs are diffed against this.
pkgname=harness-baseline
pkgver=1.0.0
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=('any')
url="https://github.com/example/harness-baseline"
license=('MIT')
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')

build() {
  cd "$srcdir/harness-baseline-1.0.0"
  make
}

package() {
  cd "$srcdir/harness-baseline-1.0.0"
  make DESTDIR="$pkgdir" install
}
