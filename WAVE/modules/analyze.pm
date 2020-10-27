# Module for Performing  file to parse the configuration settings

#!/usr/bin/perl -wT
package analyze;

use strict;
use warnings;
use URI::Escape;	# Mandetory for URL Encoding and Decoding
use report;

our (@XSS_findings, @resp_split_finding);

#----------------------------------------------------------------------------------
# 1. Function analyzing XSS vulnerability / Response Splitting

sub XSS_attack {
	my ($logs_lookup) = @_;
	my ($xss_columns) = "Request URL,Object Type,Object Name,Object Value,Response URL,Reflection at..,Reflected at..";

# print (@{$logs_lookup->{request}}[1]); Capture Request
# $resp_header = @{$logs_lookup->{response_header}}[$i]		Capture Response Header
# $resp_body = @{$logs_lookup->{response_body}}[$i]		Capture Response Body

	my ($attack_name);			# Scalar Declaration
	@XSS_findings = ();			# Array Declaration

	$attack_name="Cross Site Scripting";

	foreach my $request (@{$logs_lookup->{request}}) {

	# 1. Taking Care of all parameterised GET requests
		if ($request =~/GET\s(.*)\?(.*)\sHTTP\/\d{1}\.\d{1}/) {
			my $base_url=$1;
			my $parameters=$2;
			my $header_string=&get_header_parameters($request);
			&get_reflection("GET: ".$base_url."?".$parameters, $parameters, "Parameter", $logs_lookup);		# All Query String Parameters
			&get_reflection("GET: ".$base_url."?".$parameters, $header_string, "Header", $logs_lookup);		# All Header Parameters
		}

	# 2. Taking Care of all POST requests
		elsif ($request =~/POST\s(.*)\sHTTP\/\d{1}\.\d{1}/) {
            my $base_url=$1;
			($request =~ /Content-Type:\s{1}(.*)\s/);
			my $content_type = $1;
			if ($content_type eq "application/x-www-form-urlencoded") {
				$request =~ /Content-Length:\s{1}\d+\s+(.*)/;
		        my $parameters=$1;
		        my $header_string=&get_header_parameters($request);
				&get_reflection("POST: ".$base_url, $parameters, "Parameter", $logs_lookup);		# All POST Parameters
				&get_reflection("POST: ".$base_url, $header_string, "Header", $logs_lookup);		# All Header Parameters
			}
			elsif ( $content_type =~ /multipart\/form-data/ ) {
				( $request =~ /boundary=(.*)/ );
				my $boundary  = "--" . $1;
				my @split_req = split( $boundary, $request );
				my $parameters     = "";
				for ( my $i = 1 ; $i < $#split_req ; $i++ ) {
					( $split_req[$i] =~ /name="(.*)"\s+\s+(.*)\s+/ );
					my $params_name  = $1;
					my $params_value = $2;
					my $final        = $params_name . "=" . $params_value;
					$parameters = $parameters . $final . "&";
				}
				$parameters =~ s/&$//;
				my $header_string=&get_header_parameters($split_req[0]);
				&get_reflection("POST: ".$base_url, $parameters, "Parameter", $logs_lookup);		# All POST Parameters
				&get_reflection("POST: ".$base_url, $header_string, "Header", $logs_lookup);		# All Header Parameters
			}
		}

	# 3. Taking Care of all other GET requests which do not carry any query string parameter
		 else {
			my $header_string=&get_header_parameters($request);
	        $request =~ /GET\s(.*)\sHTTP\/\d{1}\.\d{1}/;
            my $base_url=$1;
			&get_reflection("GET: ".$base_url, $header_string, "Header", $logs_lookup);		# All Header Parameters
		}
	}

	print "\n\tStarted with XSS Reporting\n";
		&report::generate_report( $attack_name, $xss_columns, @XSS_findings ) unless ($#XSS_findings < 0) ;
	print "\tFinished with XSS Reporting\n\t-----------------------------------\n";
	#-- Calling Response Splitting Subroutine
	&respSplit_attack();
}

sub get_header_parameters {
	my ($request)=@_;
	my @headers = split (/\n/,$request);
	my $param="";
		foreach my $line (@headers) {
			if ($line =~ /^(.*?):\s+(.*)/) {
			my $header_name = $1;
			my $header_value = $2;
			my @header_value_array = split (/;/, $header_value);
#			foreach (@header_value_array) {				This part can be later modified for considering multiple parameters
#				s/^\s+//;								in the value of one header parameter.
#				s/\s+$//;
#				print $_."\n";
#			}
			my $final = $header_name."=".$header_value;
			$param = $param.$final."&";
			}
		}
	$param =~ s/&$//;
	return ($param);
}

sub get_reflection {
	my ($base_url, $parameters, $parameter_type, $logs_lookup) = @_ ;
	my (@param_array);

	@param_array = split (/\&/,$parameters);
	foreach my $param (@param_array) {
		my ($parameter, $encoded_value, $value);

		($param=~/(.*?)=(.*)/);
		$parameter=$1;
		$encoded_value=$2;		# Oh! We are looking at the URL Encoded Parameter values from Request....
		$value = uri_unescape($encoded_value); #To determine its reflection..We will URL decode thses values

		# Searching through the all Responses (body part)
		my $range = $#{$logs_lookup->{response_body}};

		for (my $i=0; $i<=$range; $i++) {
			my $resp_body = (@{$logs_lookup->{response_body}}[$i]);
			my $request = (@{$logs_lookup->{request}}[$i]);
			my @resp_body_array=split(/\n/,$resp_body);
			foreach my $reflection (@resp_body_array) {
				if ($reflection =~ /\Q$value\E/) {
					$request =~ /(GET|POST)\s{1}(.*)\s{1}HTTP\/\d{1}\.\d{1}/;
					my $relection_url = $2;
					my $sentence = "$base_url-:-$parameter_type-:-$parameter-:-$value-:-$relection_url-:-Body-:-$reflection";
					push (@XSS_findings, $sentence);
				}
			}
		}

		# Searching through the all Responses (Header part)
		for (my $i=0; $i<=$range; $i++) {	# Range will be same as number of total headers will be equal to number of responses
			my $resp_header = (@{$logs_lookup->{response_header}}[$i]);
			my $request = (@{$logs_lookup->{request}}[$i]);
			my @resp_header_array=split(/\n/,$resp_header);
			foreach my $reflection (@resp_header_array) {
				if ($reflection =~ /\Q$value\E/) {
					$request =~ /(GET|POST)\s{1}(.*)\s{1}HTTP\/\d{1}\.\d{1}/;
					my $relection_url = $2;
					my $sentence = "$base_url-:-$parameter_type-:-$parameter-:-$value-:-$relection_url-:-Header-:-$reflection";
					push (@XSS_findings, $sentence);

					# Capturing Response Splitting vulnerable parameters
					push (@resp_split_finding, $sentence);
				}
			}
		}
	}
}

sub respSplit_attack {
	my ($xss_columns) = "Request URL,Object Type,Object Name,Object Value,Response URL,Reflection at..,Reflected at..";
	my $attack_name = "RESPONSE SPLITTING";
	print "\tStarted with Response Splitting Reporting\n";
	&report::generate_report( $attack_name, $xss_columns, @resp_split_finding ) unless ( $#resp_split_finding < 0 );
	print "\tFinished with Response Splitting Reporting\n\n";
}

#----------------------------------------------------------------------------------
# 2. Function analyzing Miscellaneous vulnerabilities
	#-- 	1. Check for Cookie Attributes
	#--		2. Check for Response Banners (Server)
	#--		3. Check for Browser Cache
	#--		4. Check for Autocomplete Attributes

sub MISC_attack {

	my ($logs_lookup) = @_;

	my ($X_powered_banner, $server_banner, $X_dotnet_banner, $cookie, $cache_control_attribute, $pragma_control_attribute);
	my (@server_banner_finding, @Xpower_finding, @Xaspnet_finding, @cache_finding, @pragma_finding, @history_finding);
	my (@secure_finding, @path_finding, @domain_finding, @httponly_finding, @autocomplete_findings);

	#-- Column Names
	my ($banner_columns, $attribute_columns, $history_columns, $autocomplete_columns);
	$banner_columns = "Request URL,Banner";
	$attribute_columns = "Request URL,Status";
	$history_columns = "Request URL,Query String Parameters";
	$autocomplete_columns = "Request URL,Form Field Type,Form Field Name";
	#-- Attack Names
	my ($svrname, $xpwrname, $aspname, $securename, $domainname, $pathname, $httponlyname, $cachename, $pragmaname, $historyname, $autocompletename);
	$svrname = "Web Server Banner";
	$xpwrname = "Web Application Development Platform Banner (X-Powered-By)";
	$aspname = "ASP.NET Version Banner (X-AspNet-Version)";
	$securename = "Cookie Secure Attribute Status";
	$domainname = "Cookie Domain Attribute Status";
	$pathname = "Cookie Path Attribute Status";
	$httponlyname = "Cookie HttpOnly Attribute Status";
	$cachename = "Cache Control Attribute (Cache-Control)";
	$pragmaname = "Cache Control Attribute (Pragma)";
	$historyname = "Sensitive Information in Browsers History";
	$autocompletename = "Autocomplete";

	#-- Searching through all Responses (Header part)
	my $range = $#{$logs_lookup->{response_header}};
	for (my $i=0; $i<=$range; $i++) {
		my $resp_header = (@{$logs_lookup->{response_header}}[$i]);
		my $request = (@{$logs_lookup->{request}}[$i]);
		$request =~ /(GET|POST)\s{1}(.*)\s{1}HTTP\/\d{1}\.\d{1}/;
		my $request_url = $2;

		#------------------------------------------------------
		#-- Looking for "Server" Banner
		if ($resp_header =~ /Server:(.*)/) {
			$server_banner = $1;
			$server_banner =~ s/^\s+//;
			my $sentence = "$request_url-:-$server_banner";
			push (@server_banner_finding, $sentence);
		}
		#-- Looking for "X-Powered-By" Banner
		if ($resp_header =~ /X-Powered-By:(.*)/) {
			$X_powered_banner = $1;
			$X_powered_banner =~ s/^\s+//;
			my $sentence = "$request_url-:-$X_powered_banner";
			push (@Xpower_finding, $sentence);
		}
		#-- Looking for "X-AspNet-Version" Banner
		if ($X_powered_banner =~ /asp/i) {
			if ($resp_header =~ /X-AspNet-Version:(.*)/) {
				$X_dotnet_banner = $1;
				$X_dotnet_banner =~ s/^\s+//;
			my $sentence = "$request_url-:-$X_dotnet_banner";
			push (@Xaspnet_finding, $sentence);
			}
		}
		#----------------------------
		#-- Looking for Cookie Attribute
		if ($resp_header =~ /Set-Cookie:(.*)/) {
			$cookie = $1;
			$_ = $cookie;
			s/^\s+//;
			s/\s+$//;
			$cookie = $_;

			#-- Secure Attribute
			if ($cookie !~ /secure/i) {
				my $sentence = "$request_url-:-Not Defined";
				push (@secure_finding, $sentence);
			}
			#-- HttpOnly Attribute
			if ($cookie !~ /httponly/i) {
				my $sentence = "$request_url-:-Not Defined";
				push (@httponly_finding, $sentence);
			}
			#-- Domain Attribute
			if ($cookie !~ /domain/i) {
				my $sentence = "$request_url-:-Not Defined";
				push (@domain_finding, $sentence);

			} else {
				($cookie =~ /domain=(.*?)(;|$)/i);
				my $domain = $1;
				$request =~ /Host:\s{1}(.*)\s+/;
				my $host = $1;

				if ($domain ne $host) {
					my $sentence = "$request_url-:-Domain not Matched";
					push (@domain_finding, $sentence);
				}
			}
			#-- Path Attribute
			if ($cookie !~ /path/i) {
				my $sentence = "$request_url-:-Not Defined";
				push (@path_finding, $sentence);

			} else {
				($cookie =~ /path=(.*?)(;|$)/i);
				my $path = $1;
				if ($path eq "\/") {
					my $sentence = "$request_url-:-Global Path Set";
					push (@path_finding, $sentence);
				}
			}
		}
		#-----------------------------------

		#-- Looking for Cache control Attributes
		if ($resp_header =~ /Cache-Control:(.*)/) {
			$cache_control_attribute = $1;
			$cache_control_attribute =~ s/^\s+//;
			if ($cache_control_attribute ne "no-cache") {
				my $sentence = "$request_url-:-Not Set to 'no-cache'";
				push (@cache_finding, $sentence);
			}
		} else {
				my $sentence = "$request_url-:-Not Defined";
				push (@cache_finding, $sentence);
		}
		#-- Looking for Pragma Attribute
		if ($resp_header =~ /Pragma:(.*)/) {
			$pragma_control_attribute = $1;
			$pragma_control_attribute =~ s/^\s+//;
			if ($pragma_control_attribute ne "no-cache") {
				my $sentence = "$request_url-:-Not Set to 'no-cache'";
				push (@pragma_finding, $sentence);
			}
		} else {
				my $sentence = "$request_url-:-Not Defined";
				push (@pragma_finding, $sentence);
		}
	}
	#-----------------------------------------------------------------
	#-- Searching through all Requests
	foreach my $request (@{$logs_lookup->{request}}) {
		# 1. Taking Care of all parameterised GET requests
		if ($request =~/GET\s(.*)\?(.*)\sHTTP\/\d{1}\.\d{1}/) {
			my $base_url=$1;
			my $parameters=$2;
			$parameters =~ s/&/, /g;
			my $sentence = "$base_url-:-$parameters";
			push (@history_finding, $sentence);
		}
	}
	#-----------------------------------------------------------------
	#-- Searching through all Responses (Body part)
	my $respbody_range = $#{$logs_lookup->{response_body}};
	for (my $i=0; $i<=$respbody_range; $i++) {
		my ( $resp_body, $request, $request_url, $params, @forms, @parameters);

		@forms = ();
		$resp_body = (@{$logs_lookup->{response_body}}[$i]);
		$request = (@{$logs_lookup->{request}}[$i]);
		$request =~ /(GET|POST)\s{1}(.*)\s{1}HTTP\/\d{1}\.\d{1}/;
		$request_url = $2;

		@forms = ( $resp_body =~ /(<form\s+(?:.*?)>(?:.*?)<\/form>)/isg );
		if ($#forms >= 0) {
			foreach my $form (@forms) {
				my ($formtag);
				( $form =~ /<form\s+(.*?)>(.*?)<\/form>/isg );
				$formtag = $1;
				$params = $2;
				@parameters = ();

				if (($formtag !~ /autocomplete/i) || ($formtag =~ /autocomplete=on|autocomplete="on"/i))  {
					@parameters = ( $params =~ /(<input\s+(?:.*?)>)/isg );
					if ($#parameters >= 0) {
						foreach my $field (@parameters) {
							if (($field !~ /autocomplete/i ) || (($field !~ /autocomplete=\"off\"/i ) && ($field !~ /autocomplete=off/i ))) {
								( $field =~ /name=(.*?)(?:\s+|>)/i );
								my $name = $1;
								$name =~ s/"//g;
								( $field =~ /type=(.*?)(?:\s+|>)/i );
								my $type = $1;
								$type =~ s/"//g;

								if (($type =~ /text|password/i )) {
									my $sentence = "$request_url-:-$type-:-$name";
									push (@autocomplete_findings, $sentence);
								}
							}
						}
					}
				}
			}
		}
	}
	#-----------------------------------------------------------------

	print "\n\tStarted with Miscellaneous Issues Reporting\n";
	&report::generate_report($svrname, $banner_columns, @server_banner_finding) unless ( $#server_banner_finding < 0 ) ;
	&report::generate_report($xpwrname, $banner_columns, @Xpower_finding) unless ( $#Xpower_finding < 0 ) ;
	&report::generate_report($aspname, $banner_columns, @Xaspnet_finding) unless ( $#Xaspnet_finding < 0 ) ;
	&report::generate_report($securename, $attribute_columns, @secure_finding) unless ( $#secure_finding < 0 ) ;
	&report::generate_report($httponlyname, $attribute_columns, @httponly_finding) unless ( $#httponly_finding < 0 ) ;
	&report::generate_report($domainname, $attribute_columns, @domain_finding) unless ( $#domain_finding < 0 ) ;
	&report::generate_report($pathname, $attribute_columns, @path_finding) unless ( $#path_finding < 0 ) ;
	&report::generate_report($cachename, $attribute_columns, @cache_finding) unless ( $#cache_finding < 0 ) ;
	&report::generate_report($pragmaname, $attribute_columns, @pragma_finding) unless ( $#pragma_finding < 0 ) ;
	&report::generate_report($historyname, $history_columns, @history_finding) unless ( $#history_finding < 0 ) ;
	&report::generate_report($autocompletename, $autocomplete_columns, @autocomplete_findings) unless ( $#autocomplete_findings < 0 ) ;
	print "\tFinished with Miscellaneous Issues Reporting\n\t-----------------------------------\n";
}

#----------------------------------------------------------------------------------
# 3. Function analyzing OS Command Injection vulnerability

sub OSCmd_attack {
	my ( $payloadfile, $logs_lookup, $is_secure ) = @_;

	my (@payloads, $request_range);
	@payloads = &parsepayload::getpayloads ( $payloadfile, "OSCmdInjection" );
	$request_range = $#{$logs_lookup->{request}};

	for (my $i=0; $i<=$request_range; $i++) {
		my ( $request, $resp_header, $resp_body );
		$request = (@{$logs_lookup->{request}}[$i]);					# Request
		$resp_header = (@{$logs_lookup->{response_header}}[$i]);		# Response Header
		$resp_body = (@{$logs_lookup->{response_body}}[$i]);			# Response Body

		if ($request =~/GET\s(.*)\?(.*)\sHTTP\/\d{1}\.\d{1}/) {
			my $base_url=$1;
			my $parameters=$2;

			my @params = split (/&/, $parameters);

			foreach my $param (@params) {
				my $replace_param = $param;
				foreach my $payload (@payloads)	{
					my $param_string = $parameters;
					my $modified_request = $request;
					$param =~ s/=(.*)/=$payload/;
					$param_string =~ s/$replace_param/$param/;
					$modified_request =~ s/$parameters/$param_string/;

#					my ($response) = &web::webcommunicate($modified_request, $is_secure); 	# Calling Web module to achieve Web Communication
#					print $response;
# 					Analysis Code comes here

				}
			}
		}

	# 2. Taking Care of all POST requests
		elsif ($request =~/POST\s(.*)\sHTTP\/\d{1}\.\d{1}/) {
            my $base_url=$1;
			($request =~ /Content-Type:\s{1}(.*)\s/);
			my $content_type = $1;
			if ($content_type eq "application/x-www-form-urlencoded") {
				$request =~ /Content-Length:\s{1}\d+\s+(.*)/;
		        my $parameters=$1;

				my @params = split (/&/, $parameters);

				foreach my $param (@params) {
					my $replace_param = $param;
					foreach my $payload (@payloads)	{
						my $param_string = $parameters;
						my $modified_request = $request;
						$param =~ s/=(.*)/=$payload/;
						$param_string =~ s/$replace_param/$param/;
						$modified_request =~ s/$parameters/$param_string/;

#						my ($response) = &web::webcommunicate($modified_request, $is_secure); 	# Calling Web module to achieve Web Communication
# 						print $response;
#						Analysis Code comes here

					}
				}
			}
			elsif ( $content_type =~ /multipart\/form-data/ ) {
				( $request =~ /boundary=(.*)/ );
				my $boundary  = "--" . $1;
				my @split_req = split( $boundary, $request );
				my $parameters     = "";
				for ( my $i = 1 ; $i < $#split_req ; $i++ ) {
					( $split_req[$i] =~ /name="(.*)"\s+\s+(.*)\s+/ );
					my $params_name  = $1;
					my $params_value = $2;
					my $replace_string = $split_req[$i];
					foreach my $payload (@payloads)	{
						my $modified_request = $request;
						$replace_string =~ s/name=\"(.*)\"\n\n(.*)\n/name=\"$params_name\"\n\n$payload\n/;
						$modified_request =~ s/$split_req[$i]/$replace_string/;

#						my ($response) = &web::webcommunicate($modified_request, $is_secure); 	# Calling Web module to achieve Web Communication
# 						print $response;
# 						Analysis Code comes here


					}
				}
			}
		}
	}
}
#----------------------------------------------------------------------------------
# 4. Function analyzing URL Redirection vulnerability

sub URLRedir_attack {
	my ( $payloadfile, $logs_lookup, $is_secure ) = @_;

	my (@payloads, $request_range);
	@payloads = &parsepayload::getpayloads ( $payloadfile, "URLRedirection" );
	$request_range = $#{$logs_lookup->{request}};

	for (my $i=0; $i<=$request_range; $i++) {
		my ( $request, $resp_header, $resp_body );
		$request = (@{$logs_lookup->{request}}[$i]);					# Request
		$resp_header = (@{$logs_lookup->{response_header}}[$i]);		# Response Header
		$resp_body = (@{$logs_lookup->{response_body}}[$i]);			# Response Body

		# 1. Taking Care of all GET requests	
		if ($request =~/GET\s(.*)\?(.*)\sHTTP\/\d{1}\.\d{1}/) {
			my $base_url=$1;
			my $parameters=$2;

			my @params = split (/&/, $parameters);

			foreach my $param (@params) {
				my $replace_param = $param;
				foreach my $payload (@payloads)	{
					my $param_string = $parameters;
					my $modified_request = $request;
					$param =~ s/=(.*)/=$payload/;
					$param_string =~ s/$replace_param/$param/;
					$modified_request =~ s/$parameters/$param_string/;

#					my ($response) = &web::webcommunicate($modified_request, $is_secure); 	# Calling Web module to achieve Web Communication
#					print $response;
# 					Analysis Code comes here

				}
			}
		}

	# 2. Taking Care of all POST requests
		elsif ($request =~/POST\s(.*)\sHTTP\/\d{1}\.\d{1}/) {
            my $base_url=$1;
			($request =~ /Content-Type:\s{1}(.*)\s/);
			my $content_type = $1;
			if ($content_type eq "application/x-www-form-urlencoded") {
				$request =~ /Content-Length:\s{1}\d+\s+(.*)/;
		        my $parameters=$1;

				my @params = split (/&/, $parameters);

				foreach my $param (@params) {
					my $replace_param = $param;
					foreach my $payload (@payloads)	{
						my $param_string = $parameters;
						my $modified_request = $request;
						$param =~ s/=(.*)/=$payload/;
						$param_string =~ s/$replace_param/$param/;
						$modified_request =~ s/$parameters/$param_string/;

#						my ($response) = &web::webcommunicate($modified_request, $is_secure); 	# Calling Web module to achieve Web Communication
# 						print $response;
#						Analysis Code comes here

					}
				}
			}
			elsif ( $content_type =~ /multipart\/form-data/ ) {
				( $request =~ /boundary=(.*)/ );
				my $boundary  = "--" . $1;
				my @split_req = split( $boundary, $request );
				my $parameters     = "";
				for ( my $i = 1 ; $i < $#split_req ; $i++ ) {
					( $split_req[$i] =~ /name="(.*)"\s+\s+(.*)\s+/ );
					my $params_name  = $1;
					my $params_value = $2;
					my $replace_string = $split_req[$i];
					foreach my $payload (@payloads)	{
						my $modified_request = $request;
						$replace_string =~ s/name=\"(.*)\"\n\n(.*)\n/name=\"$params_name\"\n\n$payload\n/;
						$modified_request =~ s/$split_req[$i]/$replace_string/;

#						my ($response) = &web::webcommunicate($modified_request, $is_secure); 	# Calling Web module to achieve Web Communication
# 						print $response;
# 						Analysis Code comes here


					}
				}
			}
		}
	}
}

#----------------------------------------------------------------------------------
# 5. Function analyzing Deep URL Access vulnerability

sub DeepURL_attack {
	my ( $logs_lookup, $is_secure, $custom_error_page, $login_page, $auth_param ) = @_ ;

	my	$request_range = $#{$logs_lookup->{request}};
	for (my $i=0; $i<=$request_range; $i++) {
		my ( $request, $resp_header, $resp_body );
		$request = (@{$logs_lookup->{request}}[$i]);					# Request
		$resp_header = (@{$logs_lookup->{response_header}}[$i]);		# Response Header
		$resp_body = (@{$logs_lookup->{response_body}}[$i]);			# Response Body
		
		#-- Removing the Server side Authentication validating parameter

		# 1. Taking Care of all GET requests	
		if ($request =~/GET\s(.*)\?(.*)\sHTTP\/\d{1}\.\d{1}/) {
			my $base_url=$1;

			if ($request =~ /\?$auth_param&?/) {
				$request =~ s/$auth_param&?//;
#				my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#				print $response;
#				Analysis Code comes here
			}
			elsif ($request =~ /&$auth_param\s{1}/) {
				$request =~ s/&$auth_param//;
#				my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#				print $response;
#				Analysis Code comes here
			}
			elsif ($request =~ /\&$auth_param\&/) {
				$request =~ s/&$auth_param//;
#				my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#				print $response;
#				Analysis Code comes here
			}
			else {
				$request =~ s/\s+(.*)$auth_param(.*)//;
#				my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#				print $response;
#				Analysis Code comes here			
			}
			
		}

		# 2. Taking Care of all POST requests
		elsif ($request =~/POST\s(.*)\sHTTP\/\d{1}\.\d{1}/) {
            my $base_url=$1;
			($request =~ /Content-Type:\s{1}(.*)\s/);
			my $content_type = $1;
		
			if ($content_type eq "application/x-www-form-urlencoded") {
				if ($request =~ /\s+$auth_param&?/) {
					$request =~ s/$auth_param&?//;
#					my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#					print $response;
#					Analysis Code comes here
				}
				elsif ($request =~ /&$auth_param\s+/) {
					$request =~ s/&$auth_param//;
#					my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#					print $response;
#					Analysis Code comes here
				}
				elsif ($request =~ /\&$auth_param\&/) {
					$request =~ s/&$auth_param//;
#					my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#					print $response;
#					Analysis Code comes here
				}
				else {
					$request =~ s/\s+(.*)$auth_param(.*)//;
#					my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#					print $response;
#					Analysis Code comes here			
				}
			}

			elsif ( $content_type =~ /multipart\/form-data/ ) {
				( $request =~ /boundary=(.*)/ );
				my ( $boundary, @split_req, $name, $value );
				$boundary  = "--" . $1;
				@split_req =();
				@split_req = split( $boundary, $request );
				( $auth_param =~ /(.*)=(.*)/ );
				$name = $1;
				$value = $2;

				if ($split_req[0] =~ /\s+(.*)$auth_param(.*)/) {
					$request =~ s/\s+(.*)$auth_param(.*)//;
#					my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#					print $response;
#					Analysis Code comes here	
					last;		
				} 
				else {
					for ( my $i = 1; $i < $#split_req ; $i++ ) {
						( $split_req[$i] =~ /name="(.*)"\s+\s+(.*)\s+/ );
						my $params_name  = $1;
						my $params_value = $2;

						if (($params_name eq $name) && ($params_value eq $value))  {
							$request =~ s/$split_req[$i]$boundary//;
#							my ($response) = &web::webcommunicate($request, $is_secure); 	# Calling Web module to achieve Web Communication
#							print $response;
#							Analysis Code comes here			
							last;
						}
					}
				}
			}
		}
	}
}

#----------------------------------------------------------------------------------
# 6. Function analyzing noSSL access vulnerability

sub SSL_attack {
	my ( $logs_lookup, $is_secure, $http_port) = @_ ;

	if ($is_secure eq "1") {
		if ($http_port) {
			my	$request_range = $#{$logs_lookup->{request}};
			for (my $i=0; $i<=$request_range; $i++) {
				my ( $request, $resp_header, $resp_body );
				$request = (@{$logs_lookup->{request}}[$i]);					# Request
				$resp_header = (@{$logs_lookup->{response_header}}[$i]);		# Response Header
				$resp_body = (@{$logs_lookup->{response_body}}[$i]);			# Response Body
				
#				my ($response) = &web::webcommunicate($request, "0"); 	# Calling Web module to achieve Web Communication
# 				print $response;
# 				Analysis Code comes here
			}
# 			Reporting Code 
		} else {
			print "\t\tHey, HTTP Service is not running! Nothing to Do here.\n";
		}	
	}
	else{
		print "\t\tHey, Application runs on HTTP only! Nothing to Do here.\n";
	}
}

#----------------------------------------------------------------------------------

1;
#END
