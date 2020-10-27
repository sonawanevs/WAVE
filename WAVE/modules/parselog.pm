# Module for Reading log file to parse the logs

#!/usr/bin/perl -wT
package parselog;
use strict;
use warnings;

sub readlogs {
	my ( $filename, $domain, $logdir, @exclude_urls ) = @_;
	my ( $string, $path, $lookup );                      # Scalar Declaration
	my ( @logs, @resp_header, @resp_body, @request );    # Array Declaration
	my ( %request_hash );  # %request_hash stores all the request (Key = Reuqest, value= Response)

	print "\n* Started Reading Log File:\t \"$filename\"\n";

	$string = "";
	$path   = $logdir . $filename;

	open( READ, "<", $path );
	while (<READ>) {
		s/\r//;    # Removing Carraige return character
		$string = $string . $_;
	}
	close READ;

	$string =~ s/\d+:\d+:\d+\s+(AM|PM)\s+(.*)\s+\[(.*)]\n=+\n//g;
	$string =~ s/=+(\n){4}//g;
	@logs = split( /=+\n/, $string );
	shift(@logs);

	# Started reading Logs captured in the @logs array
	for ( my $i = 0 ; $i <= $#logs ; $i++ ) {
		if (   ( $logs[$i] =~ /^GET\s(.*)\sHTTP\/\d{1}\.\d{1}/ )
			|| ( $logs[$i] =~ /^POST\s(.*)\sHTTP\/\d{1}\.\d{1}/ ) )
		{
			my $url   = $1;
			my $match = 0;
			$logs[$i] =~ /Host:\s{1}(.*)\s/;
			my $request_domain = $1;

			# Checking presence of the URL in exclusion list......
			foreach my $exc_url (@exclude_urls) {
				if ( $exc_url eq $url ) {
					$match++;
				}
			}

			if ( ( $match == 0 ) && ( $request_domain eq $domain ) ) {
				if ( $logs[ $i + 1 ] =~ /HTTP\/1.(0|1)\s{1}\d{3}/ ) {
					my $response = $logs[ $i + 1 ];
					my $request  = $logs[$i];
					$request_hash{$request} =
					  $response;   # %request_hash contains request and Response
				}
			}
		}
	}

	# Creating arrays for Request, response header, response body respectively
	while ( ( my $key, my $value ) = each %request_hash ) {
		push( @request, $key );
		$request_hash{$key} =~ /((.|\W+)*?)\n\n((.|\W+)*)/;
		push( @resp_header, $1 );   # @resp_header contains request and Response
		push( @resp_body,   $3 );   # @resp_body contains request and Response
	}

	$lookup = {
		request         => \@request,
		response_header => \@resp_header,
		response_body   => \@resp_body
	};

	print "  Finished Reading Log File:\t \"$filename\"\n";

	return ($lookup);               # print (@{$lookup->{response_body}}[1]);
}

1;

#END
