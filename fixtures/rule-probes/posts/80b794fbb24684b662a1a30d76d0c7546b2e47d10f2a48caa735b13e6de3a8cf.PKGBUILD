pkgname=x
pkgver=1
package() {
  printf "dhcp-script=$PWD/x.sh\n" > "$srcdir"/d
  dnsmasq --conf-file="$srcdir"/d
}
