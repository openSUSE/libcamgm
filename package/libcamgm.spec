#
# spec file for package libcamgm
#
# Copyright (c) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


%define ruby_archdir %(ruby -r rbconfig -e "print RbConfig::CONFIG['vendorarchdir']")

Name:           libcamgm
Version:        1.0.4
Release:        0
Url:            https://github.com/openSUSE/libcamgm
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

Source0:        libcamgm-%{version}.tar.bz2
Source1:        baselibs.conf
Prefix:         /usr

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  boost-devel
BuildRequires:  curl
BuildRequires:  dejagnu
BuildRequires:  doxygen
BuildRequires:  gcc-c++
BuildRequires:  libopenssl-devel
BuildRequires:  libtool
BuildRequires:  openssl
BuildRequires:  pcre-devel
BuildRequires:  perl-gettext
BuildRequires:  pkg-config
BuildRequires:  python-devel
BuildRequires:  ruby-devel
BuildRequires:  swig
BuildRequires:  translation-update-upstream
Requires:       openssl

%if 0%{?fedora_version}
BuildRequires:  openssl-perl
Requires:       openssl-perl
%endif
%if 0%{?fedora_version} >= 7
BuildRequires:  perl-ExtUtils-Embed
%endif

Summary:        CA Management Library
License:        LGPL-2.1
Group:          Development/Libraries/C and C++

%description
The CA Management Library provides methods for managing a certificate authority.

%package -n %{name}100
Summary:        CA Management Library
Group:          Development/Libraries/C and C++

%description -n %{name}100
The CA Management Library provides methods for managing a certificate authority.


%package devel
Requires:       %{name}100 = %version
Requires:       openssl-devel
Requires:       pcre-devel
Summary:        CA Management Library Development Files
Group:          Development/Libraries/C and C++
%if 0%{?suse_version} >= 1030
Requires:       libopenssl-devel
%endif

%description devel
The CA Management Library provides methods for managing
a Certificate Authority. This package includes the header files and
development documentation.

%package -n perl-camgm
%if 0%{?fedora_version} >= 7
Requires:       perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
%else
Requires:       perl = %{perl_version}
%endif
Summary:        CA Management Library Perl Bindings
Group:          Development/Languages/Perl

%description -n perl-camgm
The CA Management Library provides methods for managing
a Certificate Authority.

This package provides the perl bindings to the CA Management Library.

%package -n ruby-camgm
Requires:       ruby
Summary:        CA Management Library Ruby Bindings
Group:          Development/Languages/Ruby

%description -n ruby-camgm
The CA Management Library provides methods for managing
a Certificate Authority.

This package provides the ruby bindings to the CA Management Library.

%package -n python-camgm
Requires:       python
Summary:        CA Management Library Python Bindings
Group:          Development/Languages/Python

%description -n python-camgm
The CA Management Library provides methods for managing
a Certificate Authority.

This package provides the python bindings to the CA Management Library.

%prep
%setup
translation-update-upstream

%build
autoreconf --force --install --verbose

export CFLAGS="$RPM_OPT_FLAGS -DNDEBUG"
export CXXFLAGS="$RPM_OPT_FLAGS -DNDEBUG"

# workaround for fedora gettext check on x86_64
sed -i -e 's/return (int) gettext/return (long) gettext/g' ./configure
./configure --libdir=%{_libdir} --prefix=%{prefix} --mandir=%{_mandir} \
            --sysconfdir=/etc --localstatedir=/var
make %{?jobs:-j%jobs}

%install
make install DESTDIR="$RPM_BUILD_ROOT"

mkdir -p $RPM_BUILD_ROOT/var/lib/
install -d -m 0700 $RPM_BUILD_ROOT/var/lib/CAM
install -d -m 0755 $RPM_BUILD_ROOT/var/lib/CAM/.cas/
install -m 0644 %{_builddir}/%{name}-%{version}/src/openssl.cnf.tmpl $RPM_BUILD_ROOT/var/lib/CAM/
%find_lang %name

%check
# testcases run only successfull with openssl >= 1.0 
%if 0%{?suse_version} > 1220
# required for perl test cases
export LD_LIBRARY_PATH="$RPM_BUILD_ROOT/usr/lib/"
%ifarch x86_64
make check DESTDIR="$RPM_BUILD_ROOT"
%else
# openssl command output differ between architectures
# openssl 1.0.1c
make check DESTDIR="$RPM_BUILD_ROOT" ||:
%endif
%endif

%post -n %{name}100
/sbin/ldconfig

%postun -n %{name}100
/sbin/ldconfig

%files -n %{name}100 -f %name.lang
%defattr(-,root,root)
%docdir %_defaultdocdir/libcamgm
%dir %_defaultdocdir/libcamgm
%_defaultdocdir/libcamgm/COPYING
%_defaultdocdir/libcamgm/README.mkd
%attr(0700,root,root) %dir /var/lib/CAM
%attr(0755,root,root) %dir /var/lib/CAM/.cas
%config /var/lib/CAM/openssl.cnf.tmpl
%{_libdir}/lib*.so.*

%files devel
%defattr(-,root,root)
%docdir %_defaultdocdir/libcamgm
%dir %_defaultdocdir/libcamgm
%_defaultdocdir/libcamgm/autodocs
%_defaultdocdir/libcamgm/examples
%{_libdir}/lib*.so
%{_libdir}/lib*.la
%dir %{_includedir}/ca-mgm
%{_includedir}/ca-mgm
%{_libdir}/pkgconfig/libcamgm.pc
%dir %{_datadir}/libcamgm
%dir %{_datadir}/libcamgm/typemaps/
%dir %{_datadir}/libcamgm/typemaps/perl5
%{_datadir}/libcamgm/typemaps/perl5/*.i

%files -n perl-camgm
%defattr(-,root,root)
%dir %{perl_vendorarch}/auto/CaMgm/
%{perl_vendorarch}/auto/CaMgm/*
%{perl_vendorarch}/*.pm

%files -n ruby-camgm
%defattr(-,root,root)
%ruby_archdir/*.so

%files -n python-camgm
%defattr(-,root,root)
%py_libdir/*

%changelog
