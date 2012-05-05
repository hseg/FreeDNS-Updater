# Maintainer: Gesh <moystovi@g.jct.ac.il>
pkgname=freedns-updater-git
pkgver=1.0
pkgrel=1
pkgdesc="Updates freedns.afraid.org dynamic dns domains"
arch=('any')
url="http://www.github.com/InvisibleEngineer/FreeDNS-Updater"
license=('custom:UNLICENSE')
depends=('python')
makedepends=('git')
install='INSTALL'
changelog='CHANGELOG'
source=('https://github.com/InvisibleEngineer/FreeDNS-Updater/tarball/v${pkgver}')
_gitroot="git://github.com/InvisibleEngineer/FreeDNS-Updater.git"
_gitname=FreeDNS-Updater

build() {
  cd "$srcdir"
  msg "Connecting to GIT server...."

  if [[ -d "$_gitname" ]]; then
    cd "$_gitname" && git pull origin
    msg "The local files are updated."
  else
    git clone "$_gitroot" "$_gitname"
  fi

  msg "GIT checkout done or server timeout"
  msg "Starting install..."

  rm -rf "$srcdir/$_gitname-build"
  git clone "$srcdir/$_gitname" "$srcdir/$_gitname-build"
}

package() {
  cd "$srcdir/$_gitname-build"
  mkdir -p "$pkgdir/usr/bin/"
  install freedns.py "$pkgdir/usr/bin/"
  mkdir -p "$pkgdir/usr/share/licenses/$pkgname/"
  install UNLICENSE "$pkgdir/usr/share/licenses/$pkgname/"
}

# vim:set ts=2 sw=2 et:
