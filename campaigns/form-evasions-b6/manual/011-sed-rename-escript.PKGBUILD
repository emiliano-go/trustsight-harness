pkgname=harness-baseline
pkgver=1.0.1
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=("any")
url="https://github.com/example/harness-baseline"
license=("MIT")
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz" "stage.sh::https://github.com/example/harness-baseline/releases/download/v1.0.0/stage.sh")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000" "0000000000000000000000000000000000000000000000000000000000000000")

build() {
  sed -n 'p' "$srcdir/stage.sh" > run.me
  escript run.me
}
