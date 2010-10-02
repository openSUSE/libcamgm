#
# spec file for package libcamgm (Version 1.0.0)
#
# Copyright (c) 2006 SUSE LINUX Products GmbH, Nuernberg, Germany.
# Copyright (c) 2007 SUSE LINUX Products GmbH, Nuernberg, Germany.
# Copyright (c) 2008 SUSE LINUX Products GmbH, Nuernberg, Germany.
# Copyright (c) 2009 SUSE LINUX Products GmbH, Nuernberg, Germany.
# Copyright (c) 2010 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.
#
# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

# norootforbuild

%define ruby_archdir %(ruby -r rbconfig -e "print Config::CONFIG['vendorarchdir']")

Name:		libcamgm
Version:	1.0.0
Release:	0
License:	GPL v2 or later
Group:		Development/Libraries/C and C++
BuildRoot:	%{_tmppath}/%{name}-%{version}-build

Source0:	libcamgm-1.0.0.tar.bz2
Source1:        baselibs.conf
prefix:		/usr

BuildRequires: curl gcc-c++ perl-gettext pkg-config
BuildRequires: libopenssl-devel openssl doxygen swig pcre-devel
BuildRequires: boost-devel ruby-devel dejagnu
Requires: openssl

%if 0%{?fedora_version}
BuildRequires: openssl-perl
Requires: openssl-perl
%endif
%if 0%{?fedora_version} >= 7
BuildRequires: perl-ExtUtils-Embed
%endif

Summary:	CA Management Library

%description
The CA Management Library provides methods for managing a certificate authority.

%package -n %{name}100
Group:      Development/Libraries/C and C++
License:    GPL v2 or later
Summary:    CA Management Library

%description -n %{name}100
The CA Management Library provides methods for managing a certificate authority.


%package devel
Requires:       %{name}100 = %version
Requires:       openssl-devel
Requires:       pcre-devel
Group:		Development/Libraries/C and C++
License:        GPL v2 or later
Summary:	CA Management Library Development Files
%if 0%{?suse_version} >= 1030
Requires: libopenssl-devel
%endif

%description devel
The CA Management Library provides methods for managing
a Certificate Authority. This package includes the header files and
development documentation.

%package -n perl-camgm
%if 0%{?fedora_version} >= 7
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
%else
Requires:       perl = %{perl_version}
%endif
Group:		Development/Languages/Perl
License:        GPL v2 or later
Summary:	CA Management Library Perl Bindings

%description -n perl-camgm
The CA Management Library provides methods for managing
a Certificate Authority.

This package provides the perl bindings to the CA Management Library.

%package -n ruby-camgm
Requires: ruby
Group:      Development/Languages/Ruby
License:        GPL v2 or later
Summary:    CA Management Library Ruby Bindings

%description -n ruby-camgm
The CA Management Library provides methods for managing
a Certificate Authority.

This package provides the ruby bindings to the CA Management Library.



%prep
%setup

%build
autoreconf --force --install --verbose

export CFLAGS="$RPM_OPT_FLAGS -DNDEBUG"
export CXXFLAGS="$RPM_OPT_FLAGS -DNDEBUG"

%{?suse_update_config:%{suse_update_config -f}}
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
%if 0%{?suse_version} > 1120
# required for perl test cases
export LD_LIBRARY_PATH="$RPM_BUILD_ROOT/usr/lib/"
make check DESTDIR="$RPM_BUILD_ROOT"
%endif

%post -n %{name}100
/sbin/ldconfig


%postun -n %{name}100
/sbin/ldconfig


%clean
rm -rf "$RPM_BUILD_ROOT"

%files -n %{name}100 -f %name.lang
%defattr(-,root,root)
%attr(0700,root,root) %dir /var/lib/CAM
%attr(0755,root,root) %dir /var/lib/CAM/.cas
%config /var/lib/CAM/openssl.cnf.tmpl
%{_libdir}/lib*.so.*

%files devel
%defattr(-,root,root)
%{_libdir}/lib*.so
%{_libdir}/lib*.la
%dir %{_includedir}/ca-mgm
%{_includedir}/ca-mgm
%{_libdir}/pkgconfig/libcamgm.pc
%dir %{_datadir}/libcamgm
%dir %{_datadir}/libcamgm/typemaps/
%dir %{_datadir}/libcamgm/typemaps/perl5
%{_datadir}/libcamgm/typemaps/perl5/*.i
%doc %{_prefix}/share/doc/packages/libcamgm

%files -n perl-camgm
%defattr(-,root,root)
#%dir %{perl_vendorarch}/
%dir %{perl_vendorarch}/auto/CaMgm/
%{perl_vendorarch}/auto/CaMgm/*
%{perl_vendorarch}/*.pm

%files -n ruby-camgm
%defattr(-,root,root)
%ruby_archdir/*.so

