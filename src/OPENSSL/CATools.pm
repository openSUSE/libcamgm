package OPENSSL::CATools;
use strict;
use LIMAL::LogHelper;

my $DEF_REPOS = "/var/lib/CAM/";
my $CAM_ROOT = "/var/lib/CAM/";
my $TEMPLATE = "openssl.cnf.tmpl";

sub listCA {
    $CAM_ROOT = shift || $DEF_REPOS;

    my @av_ca = ();
    if (opendir(CAMDIR, "$CAM_ROOT")) {
        foreach my $d (readdir(CAMDIR)) {
            if ($d !~ /^\./) {
                if (-d "$CAM_ROOT/$d" && -e "$CAM_ROOT/$d/openssl.cnf.tmpl") {
                    push @av_ca, $d;
                }
            }
        }
        closedir(CAMDIR);
    } else {
        die("SystemException: Can not read directory '$CAM_ROOT' '$!'");
#        return $class->SetError( code    => "Opendir_Failed",
#                                 summary => "Can not read directory '$CAM_ROOT' '$!'");
    }
    return @av_ca;
}

sub nextSerial {
    my $caName = shift || die("ValueException: Parameter 'caName' missing");
    $CAM_ROOT = shift  || $DEF_REPOS;

    my $ret = undef;
    if(!open(SER, "< $CAM_ROOT/$caName/serial")) {
        die("SystemException: Can not open '$CAM_ROOT/$caName/serial' '$!'");
    }
    while(my $l = <SER>) {
        chomp $l;
        if($l =~ /^[[:xdigit:]]+$/) {
            $ret = $l;
            last;
        }
    }
    close SER;
    if(not defined $ret) {
        die("RuntimeException: No serial number found in '$CAM_ROOT/$caName/serial'");
    } else {
        return $ret;
    }
}

sub listCertificates {
#    my $caName = shift || return $class->SetError(summary =>"Parameter 'caName' missing",
#                                                  code => "PARAM_CHECK_FAILED");
    my $caName = shift || die("ValueException: Parameter 'caName' missing");
    my @ret = ();
    
    my $indextxt = parseIndexTXT($caName);
    if (opendir(CERTDIR, "$CAM_ROOT/$caName/newcerts/")) {
        foreach my $d (readdir(CERTDIR)) {
            if ($d !~ /^\./ && -e "$CAM_ROOT/$caName/newcerts/$d") {
                $d =~ /^([[:xdigit:]]+):([[:xdigit:]]+[\d-]*)\.pem$/;
                if(!defined $1 || !defined $2) {
                    logInfo("unknown filename $d");
                    next;
                }
                my $serial = $1;
                my $md5 = $2;
                my $subject = "";
                my $certLine = {};
                $certLine->{'serial'} = $serial;
                $certLine->{'certificate'} = "$serial:$md5";
                
                foreach my $d (@$indextxt) {
                    if($d->[3] eq "$serial") {
                        $subject = $d->[5];
                        if($d->[0] eq "V") {
                            $certLine->{'status'} = "Valid";
                        } elsif($d->[0] eq "R") {
                            $certLine->{'status'} = "Revoked";
                        } elsif($d->[0] eq "E") {
                            $certLine->{'status'} = "Expired";
                        } else {
                            $certLine->{'status'} = $d->[0];
                        }
                        last;
                    }
                }
                if($subject eq "") {
#                    return $class->SetError(summary => "Can not find certificate subject.",
#                                            code => "PARSE_ERROR");
                    die("RuntimeException: Can not find certificate subject.");
                }
                my @rdns = ();
                while( $subject =~ /(.*?[^\\])(\/|$)/g ) {
                    my $dummy = $1;
                    $dummy =~ s/^\///;
                    $dummy =~ s/\\\//\//;
                    
                    push( @rdns, $dummy );
                }
                
                foreach my $rdn (@rdns) {
                    if($rdn =~ /^C=(.*)$/ && defined $1 && $1 ne "") {
                        $certLine->{'country'} = $1;
                    } elsif($rdn =~ /^ST=(.*)$/ && defined $1 && $1 ne "") {
                        $certLine->{'stateOrProvinceName'} = $1;
                    } elsif($rdn =~ /^L=(.*)$/ && defined $1 && $1 ne "") {
                        $certLine->{'localityName'} = $1;
                    } elsif($rdn =~ /^O=(.*)$/ && defined $1 && $1 ne "") {
                        $certLine->{'organizationName'} = $1;
                    } elsif($rdn =~ /^OU=(.*)$/ && defined $1 && $1 ne "") {
                        $certLine->{'organizationalUnitName'} = $1;
                    } elsif($rdn =~ /^CN=(.*)$/ && defined $1 && $1 ne "") {
                        $certLine->{'commonName'} = $1;
                    } elsif($rdn =~ /^emailAddress=(.*)$/ && defined $1 && $1 ne "") {
                        $certLine->{'emailAddress'} = $1;
                    }
                }
                push @ret, $certLine;
            }
        }
        closedir(CERTDIR);
        return \@ret;
    } else {
#        return $class->SetError( code    => "Opendir_Failed",
#                                 summary => "Can not read directory '$CAM_ROOT' '$!'");
        die("SystemException: Can not read directory '$CAM_ROOT' '$!'");
    }
}

sub listRequests {
#    my $caName = shift || return $class->SetError(summary =>"Parameter 'caName' missing",
#                                                  code => "PARAM_CHECK_FAILED");
    my $caName = shift || die("ValueException: Parameter 'caName' missing");
    my @ret = ();
    
    my $camdb = parseCAMDB($caName);
    if (opendir(REQDIR, "$CAM_ROOT/$caName/req/")) {
        foreach my $d (readdir(REQDIR)) {
            if ($d !~ /^\./ && -e "$CAM_ROOT/$caName/req/$d") {
                
                $d =~ /^([[:xdigit:]]+)-?(\d*)\.req$/;
                if(!defined $1) {
                    logInfo("unknown filename $d");
                    next;
                }
                my $md5 = $1;
                my $date = "";
                if(defined $2 && $2 ne "") {
                    $md5 = $md5."-".$2;
                    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = 
                      localtime($2);
                    $mon++;
                    $year = $year + 1900;
                    $date = "$year-$mon-$mday $hour:$min:$sec";
                }
                my $subject = "";
                my $reqLine = {};
                $reqLine->{'request'} = $md5;
                $reqLine->{'date'} = $date;
                
                foreach my $d (@$camdb) {
                    if($d->[0] eq "$md5") {
                        $subject = $d->[1];
                        last;
                    }
                }
                if($subject eq "") {
#                    return $class->SetError(summary => "Can not find request subject.",
#                                            code => "PARSE_ERROR");
                    die("RuntimeException: Can not find request subject.");
                }
                my @rdns = ();
                while( $subject =~ /(.*?[^\\])(\/|$)/g ) {
                    my $dummy = $1;
                    $dummy =~ s/^\///;
                    $dummy =~ s/\\\//\//;
                    
                    push( @rdns, $dummy );
                }
                
                foreach my $rdn (@rdns) {
                    if($rdn =~ /^C=(.*)$/ && defined $1 && $1 ne "") {
                        $reqLine->{'country'} = $1;
                    } elsif($rdn =~ /^ST=(.*)$/ && defined $1 && $1 ne "") {
                        $reqLine->{'stateOrProvinceName'} = $1;
                    } elsif($rdn =~ /^L=(.*)$/ && defined $1 && $1 ne "") {
                        $reqLine->{'localityName'} = $1;
                    } elsif($rdn =~ /^O=(.*)$/ && defined $1 && $1 ne "") {
                        $reqLine->{'organizationName'} = $1;
                    } elsif($rdn =~ /^OU=(.*)$/ && defined $1 && $1 ne "") {
                        $reqLine->{'organizationalUnitName'} = $1;
                    } elsif($rdn =~ /^CN=(.*)$/ && defined $1 && $1 ne "") {
                        $reqLine->{'commonName'} = $1;
                    } elsif($rdn =~ /^emailAddress=(.*)$/ && defined $1 && $1 ne "") {
                        $reqLine->{'emailAddress'} = $1;
                    }
                }
                push @ret, $reqLine;
            }
        }
        closedir(REQDIR);
        return \@ret;
    } else {
#        return $class->SetError( code    => "Opendir_Failed",
#                                 summary => "Can not read directory '$CAM_ROOT' '$!'");
        die("SystemException: Can not read directory '$CAM_ROOT' '$!'");
    }
}

sub checkKey {
#    my $caName = shift || return $class->SetError(summary =>"Parameter 'caName' missing",
#                                                  code => "PARAM_CHECK_FAILED");
#    my $data = shift || return $class->SetError(summary =>"Parameter 'data' missing",
#                                                code => "PARAM_CHECK_FAILED");
    my $caName = shift || die("ValueException: Parameter 'caName' missing");
    my $data = shift   || die("ValueException: Parameter 'data' missing");
    
    if(not defined $data->{'PASSWORD'}) {
#        return $class->SetError(summary =>"Parameter 'PASSWORD' missing",
#                                code => "PARAM_CHECK_FAILED");
        die("ValueException: Parameter 'PASSWORD' missing");
    }
    $ENV{'PASSWORD'} = $data->{'PASSWORD'};
    if(defined $data->{'CACERT'}) {
        my $command ="openssl rsa -noout -in ";
        $command .= "$CAM_ROOT/$caName/cacert.key ";
        $command .= "-passin env:PASSWORD ";
        my $ret = `$command 2>/dev/null`;
        if($? != 0) {
            delete( $ENV{'PASSWORD'} );
#            return $class->SetError(summary =>"Wrong password",
#                                    code => "PARAM_CHECK_FAILED");
            return 0;
        } else {
            delete( $ENV{'PASSWORD'} );
            return 1;
        }
    } elsif(defined $data->{'CERT'}) {
        $data->{'CERT'} =~ /^[[:xdigit:]]+:([[:xdigit:]]+[\d-]*)$/;
        if(not defined $1) {
#            return $class->SetError(summary => "Can not parse certificate name",
#                                    code => "PARSING_ERROR");
            die("RuntimeException: Can not parse certificate name");
        }
        my $keyname = $1;
        
        if(!-e "$CAM_ROOT/$caName/keys/".$keyname.".key") {
            delete( $ENV{'PASSWORD'} );
#            return $class->SetError(summary =>"Key '".$keyname.".key' does not exist in CA '$caName'",
#                                    code => "PARAM_CHECK_FAILED");
            die("RuntimeException: Key '".$keyname.".key' does not exist in CA '$caName'");
        }
        my $command ="openssl rsa -noout -in ";
        $command .= "$CAM_ROOT/$caName/keys/".$keyname.".key ";
        $command .= "-passin env:PASSWORD ";
        my $ret = `$command 2>/dev/null`;
        if($? != 0) {
            delete( $ENV{'PASSWORD'} );
#            return $class->SetError(summary =>"Wrong password",
#                                    code => "PARAM_CHECK_FAILED");
            return 0;
        } else {
            delete( $ENV{'PASSWORD'} );
            return 1;
        }
    } else {
#        return $class->SetError(summary =>"Missing 'CACERT' or 'CERT' parameter",
#                                code => "PARAM_CHECK_FAILED");
        die("ValueException: Missing 'CACERT' or 'CERT' parameter");
    }
}

sub createCaInfrastructure {
#    my $caName = shift || return $class->SetError(summary => "Missing value caName",
#                                                  code => "PARAM_CHECK_FAILED");
    my $caName = shift || die("ValueException: Missing value caName");
    $CAM_ROOT  = shift || $DEF_REPOS;

print STDERR "CAM_ROOT = $CAM_ROOT\n";
    
    if( not defined createCaInf($caName)) {
        return 0;
    }
    return 1;
}

sub addCAM {
    my $caName = shift || die("ValueException: Missing value caName");
    my $hash   = shift || die("ValueException: Missing parameter.");
    my $md5 = $hash->{MD5} || die("ValueException: Missing parameter 'MD5'.");
    my $dn  = $hash->{DN} || die("ValueException: Missing parameter 'DN'.");

    $CAM_ROOT = $hash->{REPOSITORY} || $DEF_REPOS;
    
    my $db = parseCAMDB($caName);
#    return undef if(not defined $db);
    
    foreach my $l (@$db) {
        if($l->[0] eq $md5) {
#            return $class->SetError(summary => "Request already exist.",
#                                    code => "PARAM_CHECK_FAILED");
            die("RuntimeException: Request already exist.");
        }
    }
    
    if(!open(DB, ">> $CAM_ROOT/$caName/cam.txt")) {
#        return $class->SetError(summary => "Can not open cam.txt.",
#                                description => "$!",
#                                code => "OPEN_FAILED");
        die("SystemException: Can not open cam.txt. '$!'");
    }
    print DB "$md5 $dn\n";
    close DB;
    return 1;
}

sub delCAM {
    my $caName = shift || die("ValueException: Missing value caName");
    my $hash   = shift || die("ValueException: Missing parameter.");
    my $md5 = $hash->{MD5} || die("ValueException: Missing parameter 'MD5'.");
    $CAM_ROOT = $hash->{REPOSITORY} || $DEF_REPOS;
    
    if(!open(DB, "< /$CAM_ROOT/$caName/cam.txt")) {
#        return $class->SetError(summary => "Can not open cam.txt.",
#                                description => "$!",
#                                code => "OPEN_FAILED");
        die("SystemException: Can not open cam.txt. '$!'");
    }
    my @cam = <DB>;
    close DB;
    my @new_cam = ();
    foreach my $l (@cam) {
        if($l !~ /^$md5/) {
            push @new_cam, $l;
        }
    }
    if(!open(DB2, "> /$CAM_ROOT/$caName/cam.txt")) {
#        return $class->SetError(summary => "Can not open cam.txt.",
#                                description => "$!",
#                                code => "OPEN_FAILED");
        die("SystemException: Can not open cam.txt.'$!'");
    }
    print DB2 @new_cam;
    close DB2;
    return 1;
}


sub createCaInf {
    my $caName = shift;

print STDERR "CAM_ROOT = $CAM_ROOT\n";

    
    if( !defined $caName || ($caName eq "") || ($caName =~ /\./)) {
#        return $class->SetError( 'summary' => 'missing parameter caName' ,
#                                 'code'    => 'PARAM_CHECK_FAILED');
        die("ValueException: Missing parameter caName");
    }
    
    if (!-d $CAM_ROOT) {
#        return $class->SetError( summary => "'$CAM_ROOT' does not exist!",
#                                 code    => 'FS_ERROR') ;
        die("SystemException: '$CAM_ROOT' does not exist!");
    }

    if ( -d "$CAM_ROOT/$caName" ) {
#        return $class->SetError( summary => "'$CAM_ROOT/$caName' still exist",
#                                 code    => 'DIR_ALREADY_EXIST');
        die("SystemException: '$CAM_ROOT/$caName' still exist");
    }
    
    if (!mkdir("$CAM_ROOT/$caName", 0700)) {
#        return $class->SetError( summary => "Can not create '$CAM_ROOT/$caName' '$!'",
#                                 code    => 'CREATE_DIR_FAILED') ;
        die("SystemException: Can not create '$CAM_ROOT/$caName' '$!'");
    }

    if( !open(IN, "< $CAM_ROOT/$TEMPLATE")) {
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not open '$TEMPLATE' '$!'",
#                                 code    => "OPEN_FAILED");
        die("SystemException: Can not open '$CAM_ROOT/$TEMPLATE' '$!'");
    }
    if(!open(OUT, ">  $CAM_ROOT/$caName/openssl.cnf.tmpl") ) { 
        rmdir("$CAM_ROOT/$caName");
        close IN;
#        return $class->SetError(summary => "Can not open '$CAM_ROOT/$caName/openssl.cnf.tmpl' '$!'",
#                                code    => "OPEN_FAILED");
        die("SystemException: Can not open '$CAM_ROOT/$caName/openssl.cnf.tmpl' '$!'");
    }
    while(my $l = <IN>) {
        chomp $l;
        $l .= "$caName" if($l =~ /^dir=/);
        print OUT "$l\n";
    }
    close IN;
    close OUT;

    if (!mkdir("$CAM_ROOT/$caName/certs", 0700) ) {
        unlink("$CAM_ROOT/$caName/openssl.cnf.tmpl");
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not create certificate directory '$CAM_ROOT/$caName/certs' '$!'",
#                                 code    => "MKDIR_FAILED");
        die("SystemException: Can not create certificate directory '$CAM_ROOT/$caName/certs' '$!'");
    }
    if (!mkdir("$CAM_ROOT/$caName/crl", 0700) ) {
        unlink("$CAM_ROOT/$caName/openssl.cnf.tmpl");
        rmdir("$CAM_ROOT/$caName/certs");
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not create CRL directory '$CAM_ROOT/$caName/crl' '$!'",
#                                 code    => "MKDIR_FAILED");
        die("SystemException: Can not create CRL directory '$CAM_ROOT/$caName/crl' '$!'");
    }
    if (!mkdir("$CAM_ROOT/$caName/newcerts", 0700) ) {
        unlink("$CAM_ROOT/$caName/openssl.cnf.tmpl");
        rmdir("$CAM_ROOT/$caName/crl");
        rmdir("$CAM_ROOT/$caName/certs");
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not create directory for new certificates '$CAM_ROOT/$caName/newcerts' '$!'",
#                                 code    => "MKDIR_FAILED");
        die("SystemException: Can not create directory for new certificates '$CAM_ROOT/$caName/newcerts' '$!'");
}
    if (!mkdir("$CAM_ROOT/$caName/req", 0700) ) {
        unlink("$CAM_ROOT/$caName/openssl.cnf.tmpl");
        rmdir("$CAM_ROOT/$caName/newcerts");
        rmdir("$CAM_ROOT/$caName/crl");
        rmdir("$CAM_ROOT/$caName/certs");
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not create request directory '$CAM_ROOT/$caName/req' '$!'",
#                                 code    => "MKDIR_FAILED");
        die("SystemException: Can not create request directory '$CAM_ROOT/$caName/req' '$!'");
    }
    if (!mkdir("$CAM_ROOT/$caName/keys", 0700) ) {
        unlink("$CAM_ROOT/$caName/openssl.cnf.tmpl");
        rmdir("$CAM_ROOT/$caName/req");
        rmdir("$CAM_ROOT/$caName/newcerts");
        rmdir("$CAM_ROOT/$caName/crl");
        rmdir("$CAM_ROOT/$caName/certs");
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not create key directory '$CAM_ROOT/$caName/keys' '$!'",
#                                 code    => "MKDIR_FAILED");
        die("SystemException: Can not create key directory '$CAM_ROOT/$caName/keys' '$!'");
    }


    if (!open(SR, "> $CAM_ROOT/$caName/serial") ) {
        unlink("$CAM_ROOT/$caName/openssl.cnf.tmpl");
        rmdir("$CAM_ROOT/$caName/keys");
        rmdir("$CAM_ROOT/$caName/req");
        rmdir("$CAM_ROOT/$caName/newcerts");
        rmdir("$CAM_ROOT/$caName/crl");
        rmdir("$CAM_ROOT/$caName/certs");
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not create serial file '$CAM_ROOT/$caName/serial' '$!'",
#                                 code    => "OPEN_FAILED");
        die("SystemException: Can not create serial file '$CAM_ROOT/$caName/serial' '$!'");
    }
    print SR "01";
    close SR;

    if (!open(DB, "> $CAM_ROOT/$caName/index.txt") ) {
        unlink("$CAM_ROOT/$caName/openssl.cnf.tmpl");
        unlink("$CAM_ROOT/$caName/serial");
        rmdir("$CAM_ROOT/$caName/keys");
        rmdir("$CAM_ROOT/$caName/req");
        rmdir("$CAM_ROOT/$caName/newcerts");
        rmdir("$CAM_ROOT/$caName/crl");
        rmdir("$CAM_ROOT/$caName/certs");
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not create database '$CAM_ROOT/$caName/index.txt' '$!'",
#                                 code    => "OPEN_FAILED");
        die("SystemException: Can not create database '$CAM_ROOT/$caName/index.txt' '$!'");
    }
    close DB;

    if (!open(DB2, "> $CAM_ROOT/$caName/cam.txt") ) {
        unlink("$CAM_ROOT/$caName/index.txt");
        unlink("$CAM_ROOT/$caName/openssl.cnf.tmpl");
        unlink("$CAM_ROOT/$caName/serial");
        rmdir("$CAM_ROOT/$caName/keys");
        rmdir("$CAM_ROOT/$caName/req");
        rmdir("$CAM_ROOT/$caName/newcerts");
        rmdir("$CAM_ROOT/$caName/crl");
        rmdir("$CAM_ROOT/$caName/certs");
        rmdir("$CAM_ROOT/$caName");
#        return $class->SetError( summary => "Can not create database '$CAM_ROOT/$caName/cam.txt' '$!'",
#                                 code    => "OPEN_FAILED");
        die("SystemException: Can not create database '$CAM_ROOT/$caName/cam.txt' '$!'");
    }
    close DB2;
    
    return 1;
}

sub parseIndexTXT {
#    my $class   = shift || return undef;
#    my $caName  = shift || return $class->SetError(summary =>"Missing Parameter 'caName'",
#                                                   code => "PARAM_CHECK_FAILED");
    my $caName  = shift || die("ValueException:Missing Parameter 'caName'");

    my @indextxt = ();

    if(!open(IDX, "< $CAM_ROOT/$caName/index.txt")) {
#        return $class->SetError(summary => "Cannot open Database file '$CAM_ROOT/$caName/index.txt'.",
#                                description => "$!",
#                                code => "OPEN_FAILED");
        die("SystemException: Cannot open Database file '$CAM_ROOT/$caName/index.txt'. '$!'");
    }
    my @lines = <IDX>;
    close IDX;
    
    foreach my $l (@lines) {
        $l =~ /^(\w)\s([\d\w]+)\s([\w\d,]*)\s([[:xdigit:]]+)\s(\w+)\s(.*)$/;
        my @idxrow = ();
        push @idxrow, $1, $2, $3, $4, $5, $6;
        push @indextxt, \@idxrow;
    }
    return \@indextxt;
}

sub parseCAMDB {
#    my $class   = shift || return undef;
#    my $caName  = shift || return $class->SetError(summary =>"Missing Parameter 'caName'",
#                                                   code => "PARAM_CHECK_FAILED");
    my $caName  = shift || die("ValueException:Missing Parameter 'caName'");

    my @camdb = ();

    if(!open(DB, "< $CAM_ROOT/$caName/cam.txt")) {
#        return $class->SetError(summary => "Cannot open Database file '$CAM_ROOT/$caName/cam.txt'.",
#                                description => "$!",
#                                code => "OPEN_FAILED");
        die("SystemException: Cannot open Database file '$CAM_ROOT/$caName/cam.txt'. '$!'");
    }
    my @lines = <DB>;
    close DB;
    
    foreach my $l (@lines) {
        $l =~ /^([[:xdigit:]]+[\d-]*)\s(.*)$/;
        my @row = ();
        push @row, $1, $2;
        push @camdb, \@row;
    }
    return \@camdb;
}
