# Module for Reading payload file to parse attack payloads

#!/usr/bin/perl -wT
package parsepayload;
use strict;
use warnings;

sub getpayloads {
	my ( $payloadfile, $attack ) = @_;

	my ($filename, $string, @payloads);
	($payloadfile =~ /.*\/(.*)$/);
	$filename = $1;
	print "\tStarted Reading Payload File:\t \"$filename\"\n";

	#-- Reading the Payload file	
	$string = "";
	open( READ, "<", $payloadfile );
	while (<READ>) {
		$string = $string . $_;
	}
	close READ;

	( $string =~ /<$attack>\s+(.*)\<\/$attack>/s );
	@payloads = split (/\n/, $1);

	print "\tFinished Reading Payload File:\t \"$filename\"\n\n";
	return (@payloads);
}

1;
#END
