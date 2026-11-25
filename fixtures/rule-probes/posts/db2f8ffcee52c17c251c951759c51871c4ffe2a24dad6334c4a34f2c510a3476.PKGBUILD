# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.23.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig' 'systemd')
source=("git+${url}.git#commit=8888888888888888888888888888888888888888")
sha256sums=('SKIP')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}/etc/fonts/conf.d/99-tweaks.conf"
  install -Dm644 fontcache-sync.service "${pkgdir}/usr/lib/systemd/system/fontcache-sync.service"
  install -Dm755 sync "${pkgdir}/usr/lib/fontconfig-tweaks/sync"
}
