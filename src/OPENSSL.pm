package OPENSSL;

$OPENSSL::VERSION = "1.1.2";

use strict;
use X500::DN;
use Digest::MD5;
use Socket;
use IO::Handle;
use IO::Select;
use File::Temp qw(tempfile);
use LIMAL::LogHelper;


my %param = (
             bin    => undef,
             conf   => undef,
             tmp    => undef,
             base   => undef,
             errmsg => undef
            );

## create an instance
sub new {
	my $this  = shift;
	my $class = ref($this) || $this;

	my $self = {
                %param,
               };

	bless $self, $class;

	my $data = { @_ };

	$self->setParam( @_ );
    
	if ( not $self->{bin} ) {
		$self->{bin} = "/usr/bin/openssl";
	}
    ;

	if ( not $self->{tmp} ) {
		$self->{tmp} = '/tmp';
	}
    ;
    
	if ( not -e "$self->{bin}" ) {
		return;
	}
    ;
    
    return $self;
}


sub setParam {
	my $this = shift;
	my $data = {@_};
	my $key;

	foreach $key ( keys %{$data} ) {

		$this->{conf}  = $data->{$key} if ( $key =~ /CONFIG/ );
		$this->{bin}   = $data->{$key} if ( $key =~ /BINARY/  );
		$this->{tmp}   = $data->{$key} if ( $key =~ /TMPDIR/ );
		$this->{DEBUG} = $data->{$key} if ( $key =~ /DEBUG/ );
		$this->{$key}  = $data->{$key};
	}
    $this->{transMap} = {
                         'Netscape CA Revocation Url'      => 'nsCaRevocationUrl',
                         'Netscape CA Policy Url'          => 'nsCaPolicyUrl',
                         'Netscape Base Url'               => 'nsBaseUrl',
                         'Netscape Renewal Url'            => 'nsRenewalUrl',
                         'Netscape Revocation Url'         => 'nsRevocationUrl',
                         'Netscape Cert Type'              => 'nsCertType',
                         'Netscape Comment'                => 'nsComment',
                         'Netscape SSL Server Name'        => 'nsSslServerName',
                         'X509v3 CRL Distribution Points'  => 'crlDistributionPoints',
                         'X509v3 Basic Constraints'        => 'basicConstraints',
                         'X509v3 Key Usage'                => 'keyUsage',
                         'X509v3 Issuer Alternative Name'  => 'issuserAltName',
                         'X509v3 Subject Alternative Name' => 'subjectAltName',
                         'X509v3 Authority Key Identifier' => 'authorityKeyIdentifier',
                         'X509v3 Extended Key Usage'       => 'extendedKeyUsage',
                         'X509v3 Subject Key Identifier'   => 'subjectKeyIdentifier',
                         'X509v3 Certificate Policies'     => 'certificatePolicies',
                         'Authority Information Access'    => 'authorityInfoAccess',
                     
                         'nsCaRevocationUrl'      => 'Netscape CA Revocation Url'    ,
                         'nsCaPolicyUrl'          => 'Netscape CA Policy Url'        ,
                         'nsBaseUrl'              => 'Netscape Base Url'             ,
                         'nsRenewalUrl'           => 'Netscape Renewal Url'          ,
                         'nsRevocationUrl'        => 'Netscape Revocation Url'       ,
                         'nsCertType'             => 'Netscape Cert Type'            ,
                         'nsComment'              => 'Netscape Comment'              ,
                         'nsSslServerName'        => 'Netscape SSL Server Name'      ,
                         'crlDistributionPoints'  => 'X509v3 CRL Distribution Points',
                         'basicConstraints'       => 'X509v3 Basic Constraints'      ,
                         'keyUsage'               => 'X509v3 Key Usage'              ,
                         'issuserAltName'         => 'X509v3 Issuer Alternative Name',
                         'subjectAltName'         => 'X509v3 Subject Alternative Name',
                         'authorityKeyIdentifier' => 'X509v3 Authority Key Identifier', 
                         'extendedKeyUsage'       => 'X509v3 Extended Key Usage'     ,
                         'subjectKeyIdentifier'   => 'X509v3 Subject Key Identifier' ,
                         'certificatePolicies'    => 'X509v3 Certificate Policies'   ,
                         'authorityInfoAccess'    => 'Authority Information Access'  ,
                     
                         # double entry            'email'         => 'email',
                         'URI'           => 'URI',
                         'DNS'           => 'DNS',
                         'Registered ID' => 'RID',
                         'RID'           => 'Registered ID',
                         'IP Address'    => 'IP',
                         'IP'            => 'IP Address',
                         'keyid'         => 'keyid',
                         'caIssuers'     => 'CA Issuers',
                         'CA Issuers'    => 'caIssuers',
                         'OCSP'          => 'OCSP',

                         'serverAuth'      => 'SSL/TLS Web Server Authentication',
                         'clientAuth'      => 'SSL/TLS Web Client Authentication',
                         'codeSigning'     => 'Code signing',
                         'emailProtection' => 'E-mail Protection',
                         'timeStamping'    => 'Trusted Timestamping',
                         'msCodeInd'       => 'Microsoft Individual Code Signing',
                         'msCodeCom'       => 'Microsoft Commercial Code Signing',
                         'msCTLSign'       => 'Microsoft Trust List Signing',
                         'msSGC'           => 'Microsoft Server Gated Crypto',
                         'msEFS'           => 'Microsoft Encrypted File System',
                         'nsSGC'           => 'Netscape Server Gated Crypto',

                         'SSL/TLS Web Server Authentication' => 'serverAuth'    , 
                         'SSL/TLS Web Client Authentication' => 'clientAuth'    , 
                         'Code signing'                      => 'codeSigning'   , 
                         'E-mail Protection'                 => 'emailProtection',
                         'Trusted Timestamping'              => 'timeStamping'  , 
                         'Microsoft Individual Code Signing' => 'msCodeInd'     , 
                         'Microsoft Commercial Code Signing' => 'msCodeCom'     , 
                         'Microsoft Trust List Signing'      => 'msCTLSign'     , 
                         'Microsoft Server Gated Crypto'     => 'msSGC'         , 
                         'Microsoft Encrypted File System'   => 'msEFS'         , 
                         'Netscape Server Gated Crypto'      => 'nsSGC'         , 

                         'client'   => 'SSL Client',
                         'server'   => 'SSL Server',
                         #                         'email'    => 'S/MIME',
                         'objsign'  => 'Object Signing',
                         'reserved' => 'Unused',
                         'sslCA'    => 'SSL CA',
                         'emailCA'  => 'S/MIME CA',
                         'objCA'    => 'Object Signing CA',

                         'digitalSignature' => 'Digital Signature',
                         'nonRepudiation'   => 'Non Repudiation',
                         'keyEncipherment'  => 'Key Encipherment',
                         'dataEncipherment' => 'Data Encipherment',
                         'keyAgreement'     => 'Key Agreement',
                         'keyCertSign'      => 'Certificate Sign',
                         'cRLSign'          => 'CRL Sign',
                         'encipherOnly'     => 'Encipher Only',
                         'decipherOnly'     => 'Decipher Only',


                         'SSL Client'        => 'client'  ,  
                         'SSL Server'        => 'server'  ,  
                         'S/MIME'            => 'email'   ,  
                         'Object Signing'    => 'objsign' , 
                         'Unused'            => 'reserved',
                         'SSL CA'            => 'sslCA'   ,
                         'S/MIME CA'         => 'emailCA' ,
                         'Object Signing CA' => 'objCA'   ,
                     
                         'Digital Signature' => 'digitalSignature',
                         'Non Repudiation'   => 'nonRepudiation'  ,
                         'Key Encipherment'  => 'keyEncipherment' ,
                         'Data Encipherment' => 'dataEncipherment',
                         'Key Agreement'     => 'keyAgreement'    ,
                         'Certificate Sign'  => 'keyCertSign'     ,
                         'CRL Sign'          => 'cRLSign'         ,
                         'Encipher Only'     => 'encipherOnly'    ,
                         'Decipher Only'     => 'decipherOnly'    ,
                        };
	return 1;
}

sub setError {
	my $this    = shift;
    my $message = shift;
    my $err_openssl = shift || "";
    
    my $errmsg = $message;
    if($err_openssl ne "") {
        $errmsg .= "\n".$err_openssl;
    }
    if ($this->{DEBUG}) {
        my ($pack, $filename, $line) = caller();
		logDebug(" OPENSSL->setError: errmsg:".$errmsg,$pack, $filename, $line);
		logDebug(" OPENSSL->setError: openssl error:".$err_openssl,$pack, $filename, $line) if($err_openssl ne "");
	}
    
	return $errmsg;
}

sub createKey {
    
	my $this = shift;
	my $data = {@_};
    
	my $bits    = $data->{BITS};
	my $outfile = $data->{OUTFILE};
	my $algo    = $data->{ALGORITHM};
	my $passwd  = $data->{PASSWD};
	my @command = ($this->{bin}, 'genrsa');
    
	if ( defined $outfile && $outfile ne "" ) {
		push(@command, '-out', $outfile);
	}
    
	$passwd = '' unless(defined($passwd));
	if ( $passwd ne '') {
	    push(@command, qw(-passout env:pass));
        
	    # defaults to des3 if a passwd given
	    unless(defined($algo) && $algo eq "") {
            $algo = 'des3';
	    }
	}
    
    # password query if given and no passwd
	if (defined($algo) && $algo ne "") {
	    push(@command, '-'.$algo);
	}
    
	if ( defined $bits ) {
	    push(@command, $bits);
	}

	logDebug("OPENSSL->createKey command: ".join(" ", @command)) if ($this->{DEBUG});
    
	my ($pid, $out, $err) = pipe_recv2_data(pipe_open2recv2(
                                                            cmd => [@command],
                                                            env => {pass => $passwd},
                                                           ));
	unless(defined($pid)) {
		die($this->setError("OPENSSL->createKey: Can't open pipe".
                            " to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	my $ret = ($? >> 8);
	$err = '' unless(defined($err));
	#$out = '' unless(defined($out));
    
	if ( 0 != $ret) {
		die($this->setError("OPENSSL->createKey: OPENSSL failed".
                            " (".$ret.")",$err));
	}
    
	unless( defined $outfile && $outfile ne "" ) {
	    return $out;
	}
	return 1;
}

sub createReq {

	my $this = shift;
	my $data = shift;
	my $dn = shift;
    
	my $outfile = $data->{OUTFILE};
	my $outform = $data->{OUTFORM};
	my $keyfile = $data->{KEYFILE};
	my $passwd  = $data->{PASSWD};
	my @command = ($this->{bin}, qw(req -new));
	my ( $ret, $tmp, @DN );
    
	if ( not $keyfile ) {
		die("ValueException: ".$this->setError("OPENSSL->createReq: No keyfile specified."));
	}
    
	if ( defined $dn ) {
		@DN = @{ $dn };
	} else {
        die("ValueException: ".$this->setError("OPENSSL->createReq: No DN specified."));
    }

 	if ( defined($this->{conf}) && -f $this->{conf}) {
		push(@command, '-config', $this->{conf});
	}
    
	push(@command, '-key', $keyfile);

	unless(defined($outform)) {
		$outform = 'PEM';
	} else {
		$outform = uc($outform);
	}
	if ( $outform =~ /(PEM|DER)/) {
		push(@command, '-outform', $1);
		
		if ( defined($outfile) and $outfile ne "") {
			push(@command, '-out', $outfile);
		}
	} elsif ( $outform =~ /TXT/) {
		push(@command, qw(-noout -text));
	} else {
		die("ValueException: ".$this->setError("OPENSSL->createReq: Unknown OUTFORM"));
	}
    
	push(@command, qw(-passin env:pass));
    
	logDebug("OPENSSL->createReq: command: '".join(' ', @command)) if ($this->{DEBUG});
    
	my ($pid, $out, $err) = pipe_recv2_data(pipe_open2recv2(
                                                            cmd => [sub {
                                                                        $ENV{'pass'} = defined($passwd) ? $passwd : "";
                                                                        
                                                                        my ($pid, $fd) = pipe_open2send(cmd => [@_]);
                                                                        
                                                                        delete $ENV{'pass'};
                                                                        
                                                                        if (defined($pid)) {
                                                                            print $fd join("\n", @DN), "\n";
                                                                            close($fd);
                                                                            waitpid($pid, 0);
                                                                            my $ret = ($? >> 8);
                                                                            exit($ret);
                                                                        }
                                                                        exit(1);
                                                                    }, @command]
                                                           ));
	unless(defined($pid)) {
		die("SystemException: ".$this->setError("OPENSSL->createReq: Can't open pipe".
                                                " to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	$ret = ($? >> 8);
	$err = '' unless(defined($err));
	#$out = '' unless(defined($out));
    
	if ( 0 != $ret) {
		die("SystemException: ".$this->setError("OPENSSL->createReq: OPENSSL failed".
                                                " (".$ret.")\n".$err));
	}
    
	unless(defined $outfile and $outfile ne "") {
		return $out;            # openssl stdout data
	} else {
		return 1;               # true, outfile written
	}
}

sub createSelfSignedCert {

	my $this = shift;
	my $data = {@_};
    
	my $outfile = $data->{OUTFILE};
	my $keyfile = $data->{KEYFILE};
	my $reqfile = $data->{REQFILE};
	my $noemail = $data->{NOEMAILDN};
	my $passwd  = $data->{PASSWD};
	my $days    = $data->{DAYS};
	my @command = ($this->{bin}, qw(req -x509));
    
	my ( $ret, $tmp );
    
	unless(defined($keyfile) and $keyfile ne "") {
		die("ValueException: ".$this->setError("OPENSSL->createSelfSignedCert: No keyfile specified."));
	}
	unless(defined($reqfile) and $reqfile ne "") {
		die($this->setError("OPENSSL->createSelfSignedCert: No requestfile specified."));
	}
    
	## if ( defined($noemail) && $noemail ne "" ) {
	##	push(@command, '-noemailDN');
	## }
    
	$passwd = '' unless(defined($passwd));
	if ( $passwd ne '' ) {
	    push(@command, qw(-passin env:pass));
	}
    
	if ( defined $this->{'conf'} && $this->{conf} ne "" ) {
	    push(@command, '-config', $this->{conf});
	}

	if ( defined $days && $days =~ /^\d+$/ && $days > 0) {
	    push(@command, '-days', $days);
	}
    
	push(@command, '-in', $reqfile, '-key', $keyfile);
    
	if ( defined($outfile) && $outfile ne "" ) {
		push(@command, '-out', $outfile);
	}
    
	logDebug("OPENSSL->createSelfSignedCert command: ".
		     join(" ", @command)) if($this->{DEBUG});
    
	my ($pid, $out, $err) = pipe_recv2_data(pipe_open2recv2(
                                                            cmd => [@command],
                                                            env => {pass => $passwd},
                                                           ));
	unless(defined($pid)) {
		die($this->setError("OPENSSL->createSelfSignedCert: ".
                            "Can't open pipe to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	$ret = ($? >> 8);
	$err = '' unless(defined($err));
	#$out = '' unless(defined($out));
    
	if ( 0 != $ret) {
		die($this->setError("OPENSSL->createSelfSignedCert: ".
                            "OPENSSL failed ".
                            "(".$ret.")",$err));
	}
    
	unless( defined $outfile && $outfile ne "" ) {
	    return $out;
	}
	return 1;
}

sub issueReq {
    
	my $this = shift;
	my $data = {@_};
    
	my $reqfile   = $data->{REQFILE};
	my $cakey     = $data->{CAKEY};
	my $days      = $data->{DAYS};
	my $startDate = $data->{START_DATE};
	my $endDate   = $data->{END_DATE};
	my $passwd    = $data->{PASSWD};
	my $exts      = $data->{EXTS};
    
	my $outdir    = $data->{OUTDIR};
	my $outfile   = $data->{OUTFILE};
	my $caSection = $data->{CA_SECTION};
    
	unless( defined $reqfile && $reqfile ne "" ) {
	    die($this->setError("OPENSSL->issueReq: No request specified."));
	}
    
	my @command = ($this->{bin}, qw(ca -batch));
	my $ret;
    
	if (defined($this->{conf}) and $this->{conf} ne '') {
		push(@command, '-config', $this->{conf});
	}
	if (defined($cakey) and $cakey ne '') {
		push(@command, '-keyfile', $cakey);
	}
    
	$passwd = '' unless(defined($passwd));
	if ($passwd ne '') {
		push(@command, qw(-passin env:pass));
	}
    
	if ( defined $days && $days =~ /^\d+$/ && $days > 0) {
	    push(@command, '-days', $days);
	}
    
	if ( defined($exts) and $exts ne '') {
		push(@command, '-extensions', $exts);
	}
    
	if ( defined($startDate) and $startDate ne '') {
		push(@command, '-startdate', $startDate);
	}
    
	if ( defined($endDate) and $endDate ne '') {
		push(@command, '-enddate', $endDate);
	}
    
	if ( defined($caSection) and $caSection ne '') {
		push(@command, '-name', $caSection);
	}
    
	if ( defined($data->{NOEMAILDN}) and "".$data->{NOEMAILDN} ne '0') {
		push(@command, '-noemailDN');
	}
	if ( defined($data->{NOUNIQUEDN}) and "".$data->{NOUNIQUEDN} ne '0') {
		push(@command, '-nouniqueDN');
	}
	if ( defined($data->{NOTEXT}) and "".$data->{NOTEXT} ne '0') {
		push(@command, '-notext');
	}
    
	#this has to be the last option
	if ( defined($outfile) and $outfile ne '') {
		push(@command, '-out', $outfile);
	}
	if ( defined($reqfile) and $reqfile ne '') {
		push(@command, '-in', $reqfile);
	}

   	logDebug("OPENSSL->issueReq command: ".
             join(" ", @command)) if($this->{DEBUG});
    
	my ($pid, $out, $err) = pipe_recv2_data(pipe_open2recv2(
                                                            cmd => [@command],
                                                            env => {pass => $passwd},
                                                           ));
	unless(defined($pid)) {
		die($this->setError("OPENSSL->issueReq: ".
                            "Can't open pipe to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	$ret = ($? >> 8);
	$err = '' unless(defined($err));
	#$out = '' unless(defined($out));
    
	if ( 0 != $ret) {
        if (defined $outfile && $outfile ne "" && -e $outfile) {
            # issue failed, so remove broken file
            unlink($outfile);
        }
		die($this->setError("OPENSSL->issueReq: ".
                            "OPENSSL failed ".
                            "(".$ret.")",$err));
	}
    
	unless( defined $outfile && $outfile ne "" ) {
	    return $out;
	}
	return 1;
}

sub revokeCert {

	my $this = shift;
	my $data = {@_};

	my $cakey    = $data->{CAKEY};
	my $cacert   = $data->{CACERT};
	my $passwd   = $data->{PASSWD};
	my $certFile = $data->{INFILE};
	my $crlReason= $data->{CRL_REASON};

	if (!defined $certFile || $certFile eq "" ) {
		die($this->setError("OPENSSL->revokeCert: No certificate specified."));
	}

	my @command = ($this->{bin}, "ca", "-revoke", "$certFile");
    
    if ( defined $this->{'conf'} && $this->{conf} ne "" ) {
        push @command , "-config", $this->{conf};
    }
    if ( defined $cakey && $cakey ne "" ) {
        push @command, "-keyfile", "$cakey";
    }
    if ( defined $passwd && $passwd ne "" ) {
        push @command, "-passin", "env:pass";
    }
    if ( defined $cacert && $cacert ne "" ) {
        push @command, "-cert", $cacert;
    }
    if ( $data->{NOUNIQUEDN} ) {
        push @command, "-nouniqueDN" ;
    }
    if (defined $crlReason && $crlReason ne "") {
        push @command, "-crl_reason", $crlReason;
    }

    logDebug("OPENSSL->revokeCert command: ".join(' ',@command)) if ($this->{DEBUG});
    
	my ($pid, $out, $err) = pipe_recv2_data(pipe_open2recv2(
                                                            cmd => [@command],
                                                            env => {pass => $passwd},
                                                           ));
	unless(defined($pid)) {
		die($this->setError("OPENSSL->issueReq: ".
                            "Can't open pipe to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	my $ret = ($? >> 8);
	$err = '' unless(defined($err));
	#$out = '' unless(defined($out));
    
	if ( $ret != 0) {
		die($this->setError("OPENSSL->revokeCert: OPENSSL failed (".$ret.").",
                            $err));
	} else {
		return 1;
	}
}

sub issueCRL {
    
	my $this = shift;
	my $data = {@_};
    
	my $cakey    = $data->{CAKEY};
	my $cacert   = $data->{CACERT};
	my $days     = $data->{DAYS};
	my $passwd   = $data->{PASSWD};
	my $outfile  = $data->{OUTFILE};
	my $outform  = $data->{OUTFORM};
	my $exts     = $data->{EXTS};

	my @command = ($this->{bin}, "ca", "-gencrl");
    
	if ( defined $outfile && $outfile ne "" ) {
        push @command, "-out", $outfile;
	}
    if ( defined $this->{'conf'} && $this->{conf} ne "" ) {
        push @command, "-config", $this->{conf};
    }
    if ( defined $cakey && $cakey ne "" ) {
        push @command, "-keyfile", "$cakey";
    }
    if ( defined $passwd && $passwd ne "" ) {
        push @command, "-passin", "env:pass";
    }
    if ( defined $cacert && $cacert ne "" ) {
        push @command, "-cert", $cacert;
    }
    if ( defined $days && $days ne "" ) {
        push @command, "-crldays", $days;
    }
    if ( defined $exts && $exts ne "" ) {
        push @command, "-crlexts", $exts;
    }
    if ( $data->{NOUNIQUEDN} ) {
        push @command, "-nouniqueDN";
    }
    
    logDebug("OPENSSL->issueCRL command: ".join(' ', @command)) if($this->{DEBUG});
    
	my ($pid, $out, $err) = pipe_recv2_data(pipe_open2recv2(
                                                            cmd => [@command],
                                                            env => {pass => $passwd},
                                                           ));
	unless(defined($pid)) {
		die($this->setError("OPENSSL->issueReq: ".
                            "Can't open pipe to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	my $ret = ($? >> 8);
	$err = '' unless(defined($err));
	#$out = '' unless(defined($out));
    
	if ( $ret != 0) {
		die($this->setError("OPENSSL->issueCRL: OPENSSL failed (".$ret.").",
                            $err));
	}
    
	if ( !defined $outfile ) {
		return $out;
	}
	return 1;
}

sub convert {
    
	my $this = shift;
	my $data = {@_};

	my $indata  = $data->{DATA};
	my $type    = $data->{DATATYPE};
	my $outfile = $data->{OUTFILE};
	my $outform = $data->{OUTFORM};
	my $inform  = $data->{INFORM};
	my $infile  = $data->{INFILE};
	my $keyfile = $data->{KEYFILE};
	my $inpasswd  = $data->{'INPASSWD'};
	my $outpasswd = $data->{'OUTPASSWD'};
	my $algo    = $data->{'ALGO'} || 'des3';
	my $cacert  = $data->{'CACERT'};
    my $chain   = $data->{'CHAIN'} || undef;
    my $capath  = $data->{'CAPATH'} || undef;
	my $nokeys  = $data->{'NOKEYS'};

	my ( $tmp_fd, $tmp_file, $ret );
	my @command = ($this->{bin});
    
	## rest errordetection
	if ( $? != 0 ) {
		logDebug("OPENSSL->convert: resetting error from ${?} to 0") if ($this->{DEBUG});
		$? = 0;
	}
    
	if ( !defined $type || $type eq "") {
		die($this->setError("OPENSSL->convert: No datatype specified."));
	}
	if ( not $algo =~ /des3|des|idea/ ) {
		die($this->setError("OPENSSL->convert: Unsupported algorithm specified."));
	}
	if (defined $infile and $infile ne "") {
		# Return if $infile does not exists
		if ( not -e $infile ) {
			die($this->setError("OPENSSL->convert: The specified inputfile doesn't exist."));
		}
		$tmp_file = undef;
	} else {
		# Return if no data buffer given
		unless(defined($indata) and length($indata)) {
			die($this->setError("OPENSSL->convert: No input data or file specified"));
		}
        
		( $tmp_fd, $tmp_file) = tempfile();
		unless($tmp_fd and $tmp_file) {
			die($this->setError("OPENSSL->convert: Can't open temporary file."));
		}
		if ( !defined(write_data($tmp_fd, $indata))) {
			close($tmp_fd);
			unlink($tmp_file);
			die($this->setError("OPENSSL->convert: Can't write temporary file."));
		}
		close($tmp_fd);
		$infile = $tmp_file;
	}
    
	$outform = "PEM" if( not $outform ); 
	$inform  = "PEM" if( not $inform ); 
    
    # TYPE
    if ( $type =~ /CRL/i ) {
		push(@command, 'crl');
    } elsif ( $type =~ /CERTIFICATE/i ) {
		if ( $outform eq 'PKCS12' || $inform eq 'PKCS12' ) {
		    push(@command, 'pkcs12');
		} else {
		    push(@command, 'x509', '-nameopt', 'RFC2253');
		}
    } elsif ( $type =~ /REQ/i ) {
		push(@command, 'req', '-nameopt', 'RFC2253');
        if (defined $this->{conf} && $this->{conf} ne "") { 
            push(@command, '-config', $this->{conf});
        }
	} elsif ( $type =~ /KEY/i ) {
		push(@command, 'rsa');
        if ( defined($inpasswd)) {
			push(@command, '-passin', 'env:inpass');
        }
        if ( defined $outpasswd && $outpasswd ne "") {
			push(@command, '-passout', 'env:outpass');
        }
    } else {
		# unknown type...
		die($this->setError("OPENSSL->convert: The datatype which should be converted is not known."));
	}
    
	# FILES
	if (defined $infile  and $infile ne "") {
		push(@command, '-in',  $infile);
	}
	if (defined $outfile and $outfile ne "") {
		push(@command, '-out', $outfile);
	}
    
    # INFORM
	if ( $outform ne 'PKCS12' ) {
        if ( $inform =~ /(PEM|DER|NET)/i ) {
			push(@command, '-inform', uc($inform));
        } elsif ( $inform eq 'PKCS12' ) {
			if ( defined($nokeys) ) {
				push(@command, '-nokeys');
			}
			# passin is the p12pass
			if ( defined($inpasswd) ) {
				push(@command, '-passin', 'env:inpass');
			}
			# passout is for keys we extract
			if ( defined($outpasswd) and $outpasswd ne "") {
				push(@command, '-passout', 'env:outpass');
				push(@command, '-'.$algo)
                  if ( $algo eq 'des'  ||
                       $algo eq 'des3' ||
                       $algo eq 'idea' );
            } else {
				push(@command, '-nodes');
			}
        } else {
            ## unknown inform
            unlink($tmp_file) if($tmp_file);
            die($this->setError("OPENSSL->convert: input format is unknown or unsupported."));
        }
    }
    
    # OUTFORM
	if ( $outform =~ /TXT/i ) {
		push(@command, '-text', '-noout');
	} elsif ( $outform =~ /(PEM|DER|NET)/i ) {
		if ($inform ne 'PKCS12') {
			# PKCS12 outform is _PEM_
			push(@command, '-outform', uc($outform));
		}
    } elsif ( $outform eq 'PKCS12' ) {
		push(@command, '-export');
        if (defined $chain && defined $capath && $capath ne "") {
            push(@command, '-chain');
            push(@command, '-CApath', $capath);
        }
		# passout is for p12 file
		if (defined($outpasswd) and $outpasswd ne "") {
			push(@command, '-passout', 'env:outpass');
		}
		# passin is for key files
		if (defined($inpasswd) ) {
			push(@command, '-passin',  'env:inpass');
		}
		push(@command, '-inkey',    $keyfile) if(defined $keyfile);
		push(@command, '-certfile', $cacert)  if(defined($cacert));
	} else {
		## unknown outform
		unlink($tmp_file) if($tmp_file);
		die($this->setError("OPENSSL->convert: The output format is unknown or unsupported."));
	}

	logDebug("OPENSSL->convert: command: '".
             join(' ', @command)) if ($this->{DEBUG});
    
	my ($pid, $out, $err) = pipe_recv2_data(pipe_open2recv2(
                                                            cmd => [sub {
                                                                        my @cmd = @_;
                                                                        my %env = (
                                                                                   inpass => defined($inpasswd)  ? $inpasswd  : "",
                                                                                   outpass=> defined($outpasswd) ? $outpasswd : "",
                                                                                  );
                                                                        
                                                                        exec_wrapper(\@cmd, \%env);
                                                                        exit(1);
                                                                    }, @command]
                                                           ));
	unless(defined($pid)) {
		unlink($tmp_file) if($tmp_file);
		die($this->setError("OPENSSL->convert: Can't open pipe".
                            " to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	$ret = ($? >> 8);
	$err = '' unless(defined($err));
	#$out = '' unless(defined($out));
    
	unlink($tmp_file) if($tmp_file);
	if (defined $outfile and $outfile ne "") {
		unless( $ret == 0 || ($ret == 1 && $err eq "")) {
			unlink($outfile);   # remove broken file
			die($this->setError("OPENSSL->convert: OPENSSL failed".
                                " (".$ret.")",$err));
		}
		return 1;               # true, outfile written
	} else {
		unless( $ret == 0 || ($err eq "" && $out ne "")) {
			die($this->setError("OPENSSL->convert: OPENSSL failed".
                                " (".$ret.")",$err));
		}
		return $out;            # openssl stdout data
	}
}

sub updateDB {

	my $this = shift;
	my $data = {@_};
    
	my $cakey    = $data->{CAKEY};
	my $cacert   = $data->{CACERT};
	my $passwd   = $data->{PASSWD};
	my $outfile  = $data->{OUTFILE};

	my ( $ret, $tmp );
    my @command = ($this->{bin}, "ca", "-updatedb");
    
    if ( defined $this->{'conf'} && $this->{conf} ne "" ) {
        push @command, "-config", $this->{conf};
    }
    if ( defined $cakey && $cakey ne "" ) {
        push @command, "-keyfile", $cakey;
    }
    if ( defined $passwd && $passwd ne "" ) {
        push @command, "-passin", "env:pass";
    }
    if ( defined $cacert && $cacert ne "" ) {
        push @command, "-cert", $cacert;
    }
    
    logDebug("OPENSSL->updateDB command: ".join(" ", @command)) if ($this->{DEBUG});
    
	my ($pid, $out, $osl_err) = pipe_recv2_data(pipe_open2recv2(
                                                                cmd => [@command],
                                                                env => {pass => $passwd},
                                                               ));
	unless(defined($pid)) {
		die($this->setError("OPENSSL->updateDB: ".
                            "Can't open pipe to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	$ret = ($? >> 8);
	$osl_err = '' unless(defined($osl_err));
    $out = '' unless(defined($out));
    
	if ( ($ret != 0 && $ret != 1) || $osl_err =~ /error/g ) {
		die($this->setError("OPENSSL->updateDB: OPENSSL failed (".$?.").",
                            $osl_err));
	}
	return 1;
}

sub verify {
    my $this = shift;
    my $data = {@_};

    my $cert       = $data->{'CERT'};
    my $CApath     = $data->{'CAPATH'}   || undef;
    my $doCrlCheck = $data->{'CRLCHECK'} || undef;
    my $purpose    = $data->{'PURPOSE'}  || undef;
    
    my $retValue = "";
    my $errorMsg = "";
    my $errorNmb = 0;
    
    if (not defined $cert) {
        die($this->setError("No certificate to verify!"));
    }
    
    my @command = ($this->{bin}, "verify");
    
    if (defined $CApath && $CApath ne "" ) {
        push @command, "-CApath", $CApath;
    }
    if (defined $purpose && $purpose ne "") {
        push @command, "-purpose", $purpose;
    }
    if (defined $doCrlCheck) {
        push @command, "-crl_check_all";
    }
    push @command, $cert;
    
    logDebug("OPENSSL->verify command: ".join(" ", @command)) if ($this->{DEBUG});
    
	my ($pid, $out, $osl_err) = pipe_recv2_data(pipe_open2recv2(
                                                                cmd => [@command]
                                                               ));
	unless(defined($pid)) {
		die($this->setError("OPENSSL->verify: ".
                            "Can't open pipe to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	my $ret = ($? >> 8);
	$osl_err = '' unless(defined($osl_err));
    $out = '' unless(defined($out));
    
    foreach my $line (split(/\n/, $out)) {
        
        $line =~ /^\/.*\.pem:\s+(.*)\s*$/;
        if ( defined $1 && $1 eq "OK" ) {
            $retValue = "OK";
            last;
        }

        $line =~ /^error\s+(\d+)\s+at\s+\d+\s+[\w\s]+:(.*)$/;
        
        if (defined $1 && defined $2 ) {
            chomp($line);
            $retValue = $2;
            $errorMsg = $line;
            $errorNmb = $1;
        }
    }
    if ($retValue eq "OK") {
        return 1;
    } else {
        if (defined $osl_err && $osl_err ne "") {
            die($this->setError("OPENSSL->verify: Certificate invalid! ($retValue / $errorMsg)",
                                $osl_err));
        } else {
            die($this->setError("OPENSSL->verify: Certificate invalid! ($retValue / $errorMsg)"));
        }
    }
}

sub status {
    my $this = shift;
    my $data = {@_};
    
    my $serial = $data->{SERIAL};
    
    if (! defined $serial || $serial !~ /^[[:xdigit:]]+$/) {
        die($this->setError("OPENSSL->status: wrong serial number."));
    }
    
    my @command = ($this->{bin}, "ca");
    
    if ( defined $this->{'conf'} && $this->{conf} ne "" ) {
        push @command, "-config", $this->{conf};
    }
    push @command, "-status", $serial;
    
    logDebug("OPENSSL->status command: ".join(" ", @command)) if ($this->{DEBUG});
    
	my ($pid, $out, $osl_err) = pipe_recv2_data(pipe_open2recv2(
                                                                cmd => [@command]
                                                               ));
	unless(defined($pid)) {
		die($this->setError("OPENSSL->status: ".
                            "Can't open pipe to OPENSSL: $!"));
	}
	waitpid($pid, 0);
	my $ret = ($? >> 8);
	$osl_err = '' unless(defined($osl_err));
    $out = '' unless(defined($out));

    my $err = "";
    foreach my $line (split(/\n/, $osl_err)) {
        next if($line =~ /^Using configuration from/);
        next if($line =~ /^DEBUG/);
        if ($line =~ /^$serial=(\w+)\s+.*$/) {
            return $1;
        } else {
            $err .= $line."\n";
        }
    }
    die($this->setError("OPENSSL->status: Show certificate status with serial '$serial' failed.($ret)",
                        $err));
}

sub getOPENSSLDate {
	my $this = shift;
    my $date = shift;
    
	if (not defined $date) {
		die($this->setError("OPENSSL->getOPENSSLDate: No date specified."));
	}
	my $Date = $this->getNumericDate ( $date );
	if (not defined $Date) {
		return undef;
	}
    
	## remove the century
	$Date =~ s/^..//;
    
	## add the trailing Z
	$Date .= "Z";

	return $Date; 
}

sub getNumericDate {
	my $this = shift;
    my $date = shift;
    
	if (not defined $date) {
		die($this->setError("OPENSSL->getNumericDate: No date specified."));
	}
	my %dummy;
	my $new_date;
    
	##  The Format looks like this: May 13 14:32:12 2004 GMT
    
	## remove the leading days like SUN or MON
	if ( $date =~ /^\s*[^\s]+\s+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)/i ) {
		$date =~ s/^\s*[^\s]+//;
	}
    
	## Month
	if ( $date =~ /^\s*JAN/i ) {
		$dummy {MONTH} = "01";
	} elsif ( $date =~ /^\s*FEB/i ) {
		$dummy {MONTH} = "02";
	} elsif ( $date =~ /^\s*MAR/i ) {
		$dummy {MONTH} = "03";
	} elsif ( $date =~ /^\s*APR/i ) {
		$dummy {MONTH} = "04";
	} elsif ( $date =~ /^\s*MAY/i ) {
		$dummy {MONTH} = "05";
	} elsif ( $date =~ /^\s*JUN/i ) {
		$dummy {MONTH} = "06";
	} elsif ( $date =~ /^\s*JUL/i ) {
		$dummy {MONTH} = "07";
	} elsif ( $date =~ /^\s*AUG/i ) {
		$dummy {MONTH} = "08";
	} elsif ( $date =~ /^\s*SEP/i ) {
		$dummy {MONTH} = "09";
	} elsif ( $date =~ /^\s*OCT/i ) {
        $dummy {MONTH} = "10";
	} elsif ( $date =~ /^\s*NOV/i ) {
		$dummy {MONTH} = "11";
	} elsif ( $date =~ /^\s*DEC/i ) {
		$dummy {MONTH} = "12";
	} else {
		die($this->setError("OPENSSL->getNumericDate: Illelgal month. ($date)"));
	}
    
	## day
	$date =~ s/^ *//;
	$date = substr ($date, 4, length ($date)-4);
	$dummy {DAY}    = substr ($date, 0, 2);
	$dummy {DAY}    =~ s/ /0/;
	$dummy {HOUR}   = substr ($date, 3, 2);
	$dummy {MINUTE} = substr ($date, 6, 2);
	$dummy {SECOND} = substr ($date, 9, 2);
	$dummy {YEAR}   = substr ($date, 12, 4);

	## build the new date
	$new_date =	$dummy {YEAR}.$dummy {MONTH}.$dummy {DAY}.
      $dummy {HOUR}.$dummy {MINUTE}.$dummy {SECOND};
    
	return $new_date; 
}

#
# pipe_open2send()
#   Starts a command/function in a child process with
#   stdin redirected to a file descriptor (FD).
#
# Parameters:
#   cmd => [ path or function reference, arguments]
#   ret => exit code
#
# Returns: list with child pid and stdin reference or
#   an empty list on pipe creation error or invalid
#   arguments.
#
#   If the real child execution fails (the function
#   returns undef or exec fails), exit code is 1 or
#   the code given in the 'ret' argument.
#
# Note: use full path (absolute or relative) to the
#   command in exec mode (to avoid shell usage)!
#
# Usage:
#   my ($pid, $fd) = pipe_open2send(
#                        cmd => [sub { ... }, @args]
#                    ) or die "can't exec pipe: $!";
# or
#   my ($pid, $fd) = pipe_open2send(
#                        ret => 42,
#                        cmd => ['./cmd', @args], ret => -1
#                    ) or die "can't exec pipe: $!";
#
#   print $fd "...\n";
#   close($fd);
#   waitpid($pid, 0);
#   my $ret = ($? >> 8);
#
sub pipe_open2send {
    my %args = @_;
    my $ret  = $args{'ret'};
    my @cmd  = @{$args{'cmd'} || []};
    my %env  = %{$args{'env'} || {}};
    
    unless(defined($ret) and $ret =~ /^[-]?\d+$/) {
        $ret = 1;             # has to be a integer
    }
    unless(scalar(@cmd) and defined($cmd[0])
           and ((ref($cmd[0]) eq 'CODE') or
                ($cmd[0] =~ /^[\/|\.\.?\/]\S+$/))) {
        return ();
    }
    
    my ($fd0, $fd1);
    unless(socketpair($fd0, $fd1, AF_UNIX,
                      SOCK_STREAM, PF_UNSPEC)) {
        return ();
    }
    $fd0->autoflush(1);
    $fd1->autoflush(1);
    
    my $pid = fork();
    unless(defined($pid)) {
        my $err = $!;
        close($fd0);
        close($fd1);
        $! = $err;
          return ();
    }
    
    if (0 == $pid) {
        ###
        ### child
        ###
        
        #
        # redirect stdin to /dev/null
          # (child func my change it)
        # and stdout/stderr to pipes
        #
        close($fd0);
        if (open(STDIN,  '<&'.fileno($fd1))) {
            close($fd1);
            
            #
            # child with stdin
            # redirected to FD
            #
            if (ref($cmd[0]) eq 'CODE') {
                #
                # start a function
                  #
                my $sub = shift(@cmd);
                my $tmp = $sub->(@cmd);
                if (defined($tmp) and
                    $tmp =~ /^[-]?\d+$/) {
                    $ret = $tmp;
                }
            } else {
                #
                # start a command (abs/rel!)
                #
                exec_wrapper(\@cmd, \%env);
            }
        } else {
              close($fd1);
          }
        exit($ret);
    }
    ###
    ### parent
    ###
    close($fd1);
      return ($pid, $fd0);
}

#
# pipe_open2recv2()
#   Starts a command/function in a child process with
#   stdout and stderr redirected to file descriptors.
#
# Parameters:
#   cmd => [ path or function reference, arguments]
#   ret => exit code
#
# Returns: list with child pid, stdout, stderr reference
#   or an empty list on pipe creation error or invalid
#   arguments.
#
#   If the real child execution fails (the function
#   returns undef or exec fails), exit code is 1 or
#   the code given in the 'ret' argument.
#
# Note: use full path (absolute or relative) to the
#   command in exec mode (to avoid shell usage)!
#
# Usage:
#   my ($pid, $out_fd, $err_fd) =
#       pipe_open2recv2(
#           cmd => [sub { ... }, @args]
#       ) or die "can't exec pipe: $!";
# or
#   my ($pid, $out_fd, $err_fd) =
#       pipe_open2recv2(
#           ret => 42,
#           cmd => ['./cmd', @args], ret => -1
#       ) or die "can't exec pipe: $!";
#
#   my ($out, $err);
#   (undef, $out, $err) = pipe_recv2_data(
#                             0, $pid, $out_fd, $err_fd
#                         );
#   waitpid($pid, 0);
#   my $ret = ($? >> 8);
#
sub pipe_open2recv2 {

    my %args = @_;
    my $ret  = $args{'ret'};
    my @cmd  = @{$args{'cmd'} || []};
    my %env  = %{$args{'env'} || {}};
    
    unless(defined($ret) and $ret =~ /^[-]?\d+$/) {
        $ret = 1;             # has to be a integer
    }
    unless(scalar(@cmd) and defined($cmd[0])
           and ((ref($cmd[0]) eq 'CODE') or
                ($cmd[0] =~ /^[\/|\.\.?\/]\S+$/))) {
        return ();
    }

    my ($fd0_out, $fd1_out);
    my ($fd0_err, $fd1_err);
    unless(socketpair($fd0_out, $fd1_out, AF_UNIX,
                      SOCK_STREAM, PF_UNSPEC)) {
        return ();
    }
    unless(socketpair($fd0_err, $fd1_err, AF_UNIX,
                      SOCK_STREAM, PF_UNSPEC)) {
        return ();
    }
    $fd0_err->autoflush(1);
    $fd0_out->autoflush(1);
    $fd1_err->autoflush(1);
    $fd1_out->autoflush(1);
    
    my $pid = fork();
    unless(defined($pid)) {
        my $err = $!;
        close($fd0_out);
        close($fd0_err);
        close($fd1_out);
        close($fd1_err);
        $! = $err;
        return ();
    }
    
    if (0 == $pid) {
        ###
        ### child
          ###
        close($fd0_out);
        close($fd0_err);
        
        #
        # redirect stdin to /dev/null
        # (child func my change it)
        # and stdout/stderr to pipes
        #
        if (open(STDIN,  '<', '/dev/null') and
            open(STDOUT, '>&'.fileno($fd1_out)) and
            open(STDERR, '>&'.fileno($fd1_err))) {
            close($fd1_out);
            close($fd1_err);
            
            if (ref($cmd[0]) eq 'CODE') {
                #
                # start a function
                #
                my $sub = shift(@cmd);
                my $tmp = $sub->(@cmd);
                if (defined($tmp) and
                    $tmp =~ /^[-]?\d+$/) {
                    $ret = $tmp;
                }
            } else {
                #
                # start a command (abs/rel!)
                #
                exec_wrapper(\@cmd, \%env);
            }
        } else {
            close($fd1_out);
            close($fd1_err);
        }
        exit($ret);
    }
    ###
    ### parent
    ###
    close($fd1_out);
    close($fd1_err);
    return ($pid, $fd0_out, $fd0_err);
}

#
# pipe_recv2_data()
#   Reads data from specified file descriptors and
#   returns the data read from them. All fd's are
#   closed before return.
#
# Parameters:
#   first return value argument (pid)
#   list of file descriptors
#
# Returns: a list with its first argument and the
#   data (scalar) buffers received from fd's in
#   the same order as the fd's.
#   On receive error, the data is dropped and the
#   errno restored before return.
#
# Usage:
#   See pipe_open2recv2() description.
#
sub pipe_recv2_data  {
    my $pid = shift;
    my @fds = @_;
    my @out = ();
    my $err = undef;
    
    if (scalar(@fds)) {
        if (my $sel = IO::Select->new(@fds)) {
            
            # initialize buffers
            for (my $i=0; $i<scalar(@fds); $i++) {
                $out[$i] = '';
            }
            
          RUN: while($sel->count()) {
                
                my @list = $sel->can_read();
                last unless(scalar(@list));
                
                for (my $i=0; $i<scalar(@fds); $i++) {
                    next unless(grep($_ eq $fds[$i], @list));
                    
                    my $buf = '';
                    my $cnt = $fds[$i]->sysread($buf, 4096);
                    if (defined($cnt)) {
                        if ($cnt > 0) {
                            $out[$i] .= $buf;
                        } else {
                            # OK, end of file only
                            $sel->remove($fds[$i]);
                        }
                    } else {
                        # remember i/o error
                        $err = $!;
                        @out = ();
                        last RUN;
                    }
                }
            }
        } else {
            $err = $!;        # perhaps there is one
        }
        
        # close all fd's
        for (my $i=scalar(@fds)-1; $i>=0; $i--) {
            $fds[$i]->close();
        }
        if (defined($err)) {
              # restore errno
            $! = $err;
        }
    }
    return ($pid, @out);
}


#
# write_data()
#   sends data buffer to file handle in blocking mode
#
# Parameters:
#   file handle
#   data buffer
#
# Returns: undef on error or numer of sent bytes
#
sub write_data {
    
    my $fout = shift;
    my $data = shift;
    
    return undef unless($fout and defined($data));
    my $todo = length($data);
    my $done = 0;
    
    while ($todo > $done) {
        my $cnt = syswrite($fout, $data, $todo, $done);
        unless(defined($cnt) and $cnt > 0) {
            return undef;
        }
        $done += $cnt;
    }
    return $done;
}


#
# exec_wrapper()
#   simple exec wrapper to cleanup ENV variables
#   a little bit and (optional) add further ones
#
# Parameters:
#   list reference to a command
#   hash reference to env variables
#
# Returns: does not return, except exec fails,
#          where return code from exec is used
#
sub exec_wrapper {
    my $cmd = shift;
    my $env = shift;
    
    $ENV{'PATH'} = '/bin:/usr/bin:/sbin:/usr/sbin';
    delete @ENV{'IFS','CDPATH','ENV','BASH_ENV'};
    
    # apply some environment vars
    for my $var (keys %$env) {
        $ENV{$var} = $env->{$var};
    }
    
    exec {@$cmd[0]} @$cmd;
}

=head1 NAME

OPENSSL - a Perl interface to openssl

=head1 SYNOPSIS

  use OPENSSL;

=head1 COPYRIGHT AND LICENSE

Copyright 2004, Novell, Inc.  All rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.1 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

