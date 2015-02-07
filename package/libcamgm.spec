#
# spec file for package libcamgm
#
# Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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


Name:           libcamgm
Version:        1.0.8
Release:        0
Summary:        CA Management Library
License:        LGPL-2.1
Group:          Development/Libraries/C and C++
Url:            https://github.com/openSUSE/libcamgm
Source0:        libcamgm-%{version}.tar.bz2
Source1:        baselibs.conf
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  boost-devel
BuildRequires:  dejagnu
BuildRequires:  doxygen
BuildRequires:  fdupes
BuildRequires:  gcc-c++
BuildRequires:  libcurl-devel
BuildRequires:  libtool
BuildRequires:  openssl-devel
BuildRequires:  pcre-devel
BuildRequires:  perl-gettext
BuildRequires:  pkg-config
BuildRequires:  python-devel
BuildRequires:  ruby-devel
BuildRequires:  swig
BuildRequires:  translation-update-upstream
Requires:       ca-certificates
Requires:       openssl
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
%if 0%{?fedora_version}
BuildRequires:  openssl-perl
BuildRequires:  perl-ExtUtils-Embed
Requires:       openssl-perl
%endif

%description
The CA Management Library provides methods for managing a certificate authority.

%package -n %{name}100
Summary:        CA Management Library
Group:          Development/Libraries/C and C++

%description -n %{name}100
The CA Management Library provides methods for managing a certificate authority.

%package devel
Summary:        CA Management Library Development Files
Group:          Development/Libraries/C and C++
Requires:       %{name}100 = %{version}
Requires:       openssl-devel
Requires:       pcre-devel

%description devel
The CA Management Library provides methods for managing
a Certificate Authority. This package includes the header files and
development documentation.

%package -n perl-camgm
Summary:        CA Management Library Perl Bindings
Group:          Development/Languages/Perl
%if 0%{?fedora_version}
Requires:       perl(:MODULE_COMPAT_%(eval "`perl -V:version`"; echo $version))
%else
Requires:       perl = %{perl_version}
%endif

%description -n perl-camgm
The CA Management Library provides methods for managing
a Certificate Authority.

This package provides the perl bindings to the CA Management Library.

%package -n ruby-camgm
Summary:        CA Management Library Ruby Bindings
Group:          Development/Languages/Ruby
Requires:       ruby

%description -n ruby-camgm
The CA Management Library provides methods for managing
a Certificate Authority.

This package provides the ruby bindings to the CA Management Library.

%package -n python-camgm
Summary:        CA Management Library Python Bindings
Group:          Development/Languages/Python
Requires:       python

%description -n python-camgm
The CA Management Library provides methods for managing
a Certificate Authority.

This package provides the python bindings to the CA Management Library.

%prep
%setup -q
translation-update-upstream

%build
autoreconf -fvi

export CFLAGS="%{optflags} -DNDEBUG"
export CXXFLAGS="%{optflags} -DNDEBUG"

# workaround for gettext check on x86_64
sed -i -e 's/return (int) gettext/return (long) gettext/g' configure

%configure
make %{?_smp_mflags}

%install
make DESTDIR=%{buildroot} install %{?_smp_mflags}

mkdir -p %{buildroot}%{_localstatedir}/lib/
install -d -m 0700 %{buildroot}%{_localstatedir}/lib/CAM
install -d -m 0755 %{buildroot}%{_localstatedir}/lib/CAM/.cas/
install -m 0644 %{_builddir}/%{name}-%{version}/src/openssl.cnf.tmpl %{buildroot}%{_localstatedir}/lib/CAM/
%find_lang %{name}
%fdupes %{buildroot}

%check
# required for perl test cases
export LD_LIBRARY_PATH="%{buildroot}%{_libexecdir}/"
%ifarch x86_64
make check DESTDIR=%{buildroot} %{?_smp_mflags}
%else
# openssl command output differ between architectures
# openssl 1.0.1c
make check DESTDIR=%{buildroot} %{?_smp_mflags} ||:
%endif

%post -n %{name}100 -p /sbin/ldconfig

%postun -n %{name}100 -p /sbin/ldconfig

%files -n %{name}100 -f %{name}.lang
%defattr(-,root,root)
%docdir %{_defaultdocdir}/libcamgm
%dir %{_defaultdocdir}/libcamgm
%{_defaultdocdir}/libcamgm/COPYING
%{_defaultdocdir}/libcamgm/README.mkd
%attr(0700,root,root) %dir %{_localstatedir}/lib/CAM
%attr(0755,root,root) %dir %{_localstatedir}/lib/CAM/.cas
%config %{_localstatedir}/lib/CAM/openssl.cnf.tmpl
%{_libdir}/lib*.so.*

%files devel
%defattr(-,root,root)
%docdir %{_defaultdocdir}/libcamgm
%dir %{_defaultdocdir}/libcamgm
%{_defaultdocdir}/libcamgm/autodocs
%{_defaultdocdir}/libcamgm/examples
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
%{rb_vendorarchdir}/*.so

%files -n python-camgm
%defattr(-,root,root)
%{python_sitearch}/*

%changelog
