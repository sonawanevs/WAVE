# Module for Generating Report file

#!/usr/bin/perl -wT
package report;
use strict;
use HTML::Entities;

our ($no, $logfile, $path, $file_path);

#---------------------------------------------------------------
sub generate_HTML_page {
	($logfile, $path) = @_;
	$no=0;
	$file_path = $path.$logfile.".html";
	open (HTML, ">", $file_path) or die "File error: $!";
	print HTML <<ENDHTML;
<html>
<head>
	<title>Vulnerability Report :- $logfile </title>
</head>
<body>
<!-- Start Code -->
	<table border="0" width="100%" height="100%" cellpadding="2">
		<tr>
		    <td height="14%" width="10%" valign="top"><img alt="WAVE - Web Application Vulnerability analyzing Engine" src="../images/wave.png" height="70" width="170"></td>
		    <td height="14%" width="80%" valign="top"></td>
		</tr>
        <tr>
            <td valign="top"  colspan="3" >
           		<div style="width: auto; height: 440px; overflow: auto; border: 1px solid black;">
ENDHTML
	close HTML;
}

#---------------------------------------------------------------
sub generate_report {
	# Initial variables will capture the information
	my ($attack_name, $columns, @vulnerabilities) = @_;
	
	my @column_names = split ( /,/ , $columns );

	$no++;
	my $priv_link =$no-1;
	my $next_link = $no+1;
	my $count =1;
	open (HTML, "+>>", $file_path) or die "File error: $!";

print HTML <<ENDHTML;

<!-- Mid Code -->

					<h4><span id="$no"><font color="black" face="Impact" size="4">$no. $attack_name&nbsp;&nbsp;<a href="#$priv_link"><font color="gray" face="Impact" size="1">PREVIOUS</a></font>&nbsp;&nbsp;<a href="#$next_link"><font color="gray" face="Impact" size="1">NEXT</a></font></font></span></h4>
                <table border="1" cellpadding="5">
                    <!-- Single Loop for <tr> as only one row for Displaying Column names-->
                    <tr>
ENDHTML


						foreach my $column_name (@column_names)	{
print HTML <<ENDHTML;		
		                    <td valign="top">
		                        <h5><b><font color="maroon" face="courier" size="2">$column_name</font></b></h5>
		                    </td>
ENDHTML
						}


print HTML <<ENDHTML;	
                    </tr>

                    <!-- FOR Loop for <tr> as well as it depends on the number of vulnerabilities found -->
ENDHTML


					foreach my $entry (@vulnerabilities)	{
					my @entry_array = split (/-:-/, $entry);
print HTML <<ENDHTML;	
		                <tr>
ENDHTML


						foreach my $data (@entry_array)	{
							my	$data_entry = encode_entities($data);
print HTML <<ENDHTML;	
		                    <td valign="top">
		                        <h5><b><font color="blue" face="Impact" size="1">$data_entry</font></b></h5>
		                    </td>
ENDHTML
						}


print HTML <<ENDHTML;	
		                </tr>
ENDHTML
					}


print HTML <<ENDHTML;		                
                </table>


ENDHTML

	close HTML;
}
#---------------------------------------------------------------
sub close_HTML_page {
	open (HTML, "+>>", $file_path) or die "File error: $!";
	print HTML <<ENDHTML;

<!-- End Code -->
				</div>
            </td>
        </tr>
	    <tr>
	        <td height="1%" width="100%" valign="top" colspan="3" align="center"><font face="Impact" size="2"></font></td>
	    </tr>
	</table>
</body>

</html>
ENDHTML
	close HTML;
}

1;
#END
