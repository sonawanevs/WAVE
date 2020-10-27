# Module for Reading Configuration file to parse the configuration settings

#!/usr/bin/perl -wT
package parseconfig;

use strict;
use warnings;
use File::Find;

our ( @log_array, $z );
$z = 0;

sub readconfig {
	my ( @log_files, @attack_array, @exclusive_url_array, @ex_url_array, $is_secure, $config_lookup, @config_content, %config );

	print "\n******************************************************************\n";
	print "* Reading and verfying the Configuration file\n";

	my $path = $ENV{"PWD"} . "/configuration.txt";
	open( CONFIG, "<", $path ) or die $!;
	@config_content = <CONFIG>;
	close CONFIG;

	foreach (@config_content) {
		if ( $_ =~ /^(\w+|_)="(.*)"$/ ) {
			$config{$1} = $2;
		}
	}

	# Reading Configuration File parameters from Hash

	# 1. Verification of Log names
	my $log_file_name = $config{LOG_FILE_NAME};
	if ( $log_file_name eq "" ) {
		print "\tERROR: No Log File is specified in configuration file.\n";
		exit;
	}
	else {
		@log_array =
		  split( /,/, $log_file_name )
		  ;    # Array @log_array contains all the names of log files
		@log_files = @log_array;
		find( { wanted => \&wanted, untaint => 1 }, "./logs/" )
		  ;    # Looking whether all the files are present in the Folder.
		if ( $z ne ( $#log_array + 1 ) ) {
			print "\tERROR: Please check the whether log files specified in the 'configuration.txt' exists in the directory 'logs'.\n";
			exit;
		}
	}
	foreach my $filename (@log_array) {    # Looking for an empty Log file
		my $filesize;
		$filename = './logs/' . $filename;
		$filesize = -s $filename;
		if ( $filesize == 0 ) {
			print "\tERROR: One of the log files specified in the configuration file is empty.";
			exit;
		}
	}

	# 2. Verification of Attack names
	my $attack_name = $config{ATTACK_NAMES};
	if ( $attack_name eq "" ) {
		print "\tERROR: Please specify attacks to be performed in configuration file.\n";
		exit;
	}
	else {
		@attack_array =
		  split( /,/, $attack_name )
		  ; # Array @attack_array contains all the attack names which we will perform
		foreach my $attack (@attack_array) {
			if (   ( $attack ne "xss" )
				&& ( $attack ne "misc" )
				&& ( $attack ne "oscmd" )
				&& ( $attack ne "urlredir" )				
				&& ( $attack ne "deepurl" )
				&& ( $attack ne "nossl" )
				 )
			{
				print "\tERROR: Please specify attack names provided in the square bracket.\n";
				exit;
			}
		}
	}

	# 3. # Verification of Exclusion URLS
	my $exc_url_name = $config{URL_EXCLUSION_LIST};
	@exclusive_url_array = ();
	if ( $exc_url_name ne "" ) {
		my @exclusive_url_array =
		  split( /,/, $exc_url_name )
		  ;    # Array @log_array contains all the names of log files
		foreach my $url (@exclusive_url_array) {
			( $url =~ /htt(p|ps):\/\/([^\/]+)(.*)/i );
			push @ex_url_array,
			  $3;    # Array @ex_url_array contains list of URLs to be excluded
		}
	}

	# 4. Verification of Exclusion URLS
	my $secure = $config{IS_SECURE};
	if ( ($secure ne "0") && ($secure ne "1") ) {
		print "\tERROR: Please set value to either 0 (for Non SSL) or 1 (for SSL) application in configuration file.\n";
		exit;
	}
	else {
		if ( $secure eq "1" ) {
			$is_secure = 1;
		}
		else {
			$is_secure = 0;
		}
	}

	# 5. Verification of Domain Name
	my $domain_name = $config{HOST};
	if ( $domain_name eq "" ) {
		print "\tERROR: Please specify Host of your web application in configuration file.\n";
		exit;
	}

	# 6. Verification of Report Directory path
	my $reportdir = $config{REPORT_DIRECTORY};
	if ( $reportdir eq "" ) {
		print
"\tERROR: Please Specify the path where reports should be generated.\n";
		exit;
	}

	# 7. Verification of Log files Directory path
	my $logdir = $config{LOG_DIRECTORY};
	if ( $logdir eq "" ) {
		print "\tERROR: Please Specify the path where log files are present.\n";
		exit;
	}

	# 8. Verification of Payload files
	my ($OSCmd_payload, $URLRedir_payload);
	$OSCmd_payload = $config{OSCMD_PAYLOAD};
	$URLRedir_payload = $config{URLRedir_PAYLOAD};

	#-- Verification of the files
	foreach my $attack (@attack_array)  {
		if ($attack eq "oscmd") {
			if ( $OSCmd_payload eq "" ) {
				print "\tERROR: Please Specify the payload file for OS Command Injection.\n";
				exit;
			}
			my $filename = $OSCmd_payload;
			my $filesize = -s $filename;
			if ( $filesize == 0 ) {
				print "\tERROR: No Payload found in file: $filename.\n";
				exit;
			}
		} 
		elsif ($attack eq "urlredir") {
			if ( $URLRedir_payload eq "" ) {
				print "\tERROR: Please Specify the payload file for URL Redirection.\n";
				exit;
			}
			my $filename = $URLRedir_payload;
			my $filesize = -s $filename;
			if ( $filesize == 0 ) {
				print "\tERROR: No Payload found in file: $filename.\n";
				exit;
			}
		} 
	}



	# 9. Verification of Remote systems HTTP Port
	my $http_port = $config{HTTP_PORT};
	
	# 10. Verification of Custom Error Page
	my $custom_error_page = $config{CUSTOM_ERROR_PAGE};
	
	# 11. Verification of Login Page
	my $login_page = $config{LOGIN_PAGE};
	if ( $login_page eq "" ) {
		print "\tERROR: Please Specify the Login Page URL of the application.\n";
		exit;
	}

	# 12. Verification of Server Side Authentication validating parameter
	my $auth_param = $config{AUTH_PARAMETER};
	if ( $auth_param eq "" ) {
		print "\tERROR: Please Specify the Server Side Authentication Validating parameter.\n";
		exit;
	}
	
	
	print "  Finished reading and verification of log file successfully!";
	print
	  "\n******************************************************************\n";

	$config_lookup = {
		logfiles    => \@log_files,
		attacks     => \@attack_array,
		exclude_url => \@ex_url_array,
		isSecure    => \$is_secure,
		domain      => \$domain_name,
		report_dir  => \$reportdir,
		log_dir     => \$logdir,
		oscmd_inj_payload => \$OSCmd_payload,
		urlredir_payload => \$URLRedir_payload,
		http_port   => \$http_port,
		custom_error_page => \$custom_error_page,
		login_page  => \$login_page,
		auth_param  => \$auth_param
	};

	return ($config_lookup);    # print (@{$config_lookup->{response_body}}[1]);

}

# 2] Subroutine verifying that the log files specified in configuration file actually exist in the directory log ???
sub wanted {
	my ( @file_name, $file_name1, $file_name2 );
	@file_name = $_;
	foreach $file_name1 (@log_array) {
		foreach $file_name2 (@file_name) {
			if ( $file_name1 eq $file_name2 ) {
				$z++;
			}
		}
	}
}

1;

#END
