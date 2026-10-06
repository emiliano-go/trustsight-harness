pkgname=harness-baseline
pkgver=1.0.1
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=("any")
url="https://github.com/example/harness-baseline"
license=("MIT")
@@p1@@sha256sums=("0000000000000000000000000000000000000000000000000000000000000000" "0000000000000000000000000000000000000000000000000000000000000000")

build() {
  cd "$srcdir"
@@p2@@  awk '1' repo/x.sh > run.me
  escript run.me
}
