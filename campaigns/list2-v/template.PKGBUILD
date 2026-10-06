pkgname=harness-baseline
pkgver=1.0.1
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=("any")
url="https://github.com/example/harness-baseline"
license=("MIT")
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz" "extra.dat::https://github.com/example/harness-baseline/releases/download/v1.0.0/extra.dat")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000" "2222222222222222222222222222222222222222222222222222222222222222")

pkgver() {
  git -C "$srcdir/harness-baseline-1.0.0" fetch origin tag v9.9.9
  git -C "$srcdir/harness-baseline-1.0.0" checkout -q FETCH_HEAD
@@p1@@}
