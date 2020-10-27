#!/usr/bin/perl -wT
package web;
use LWP;
use HTTP::Request;
use HTTP::Response;
use HTTP::Headers;
use HTTP::Status;
#use Crypt::SSLeay;
use strict;

sub webcommunicate {
	my ( $request, $is_secure ) = @_;
	my ( $method, $url, $parameter, $tmp_request, @headers, $req, $host, $url_relative );

	# Need some preparation for sending the Request via LWP.....
	( $request =~ /^(.*)\s(.*)\sHTTP\/\d{1}\.\d{1}(?:.*)/ );
	$method       = $1;    # $method stores the request type
	$url_relative = $2;    # $url stores the URL
	( $request =~ /Host:\s+(.*)/ );
	$host = $1;
	$host =~ s/\r//g;

	if ( $is_secure eq 1 ) {
		$url = "https://" . $host . $url_relative;    # $url stores the URL
	}
	else {
		$url = "http://" . $host . $url_relative;     # $url stores the URL
	}
		
	# Processing POST and GET request separately 
	if ( $method eq "POST" ) {
		( $request =~ /Content-Length:\s{1}\d+\s+(.*)/ );
		$parameter = $1;    # $parameter stores the request parameters
		$parameter =~ s/\r//g;
		my $test_req = $request;
		$_ = $test_req;
		s/^(.*)\s(.*)\sHTTP\/\d{1}\.\d{1}(.*)//;
		s/$parameter//;
		$tmp_request = $_; # $tmp_request stores the request headers...will be passed to header function
	}
	else {
		my $test_req = $request;
		$_ = $test_req;
		s/^(.*)\s(.*)\sHTTP\/\d{1}\.\d{1}(.*)//;
		$tmp_request = $_;
	}

	# Generating the rest Header Information
	@headers = split( /\n/, $tmp_request );
	shift(@headers);
	pop(@headers);
	pop(@headers);

	########################################################################################

	# Generating Request...........

	$req = new HTTP::Request $method, $url;    # URL

	foreach (@headers) {                       # Rest Header Information
		( $_ =~ /(.*):\s+(.*)/ );
		my $var   = $1;
		my $value = $2;
		$var   =~ s/\r//g;
		$value =~ s/\r//g;

		if ( $var !~ /Accept-Encoding|Content-Length/)  {  # Problem with LWP...
	
			$req->header( $var => $value );
		}
	}

# Adding POST Parameters if Request type is POST...Not necessary for GET as parameters will travel as QueryString
	if ( $method eq "POST" ) {
		$req->content($parameter);
	}

	print $req->as_string( );
	print "\n";

	########################################################################################

	# Generating Response...........

	my $ua  = new LWP::UserAgent;
	my $res = $ua->request($req);    # Sending Request and Capturing Response
	
	
	if ( $res->is_success ) {

		print $res->content;
		return ( $res->content );    # Return the positive response obtained from the server.

	}
	else {

		print $res->error_as_HTML;
		return ( $res->content );    # Return the positive response obtained from the server.
	}

}
1;

#END
