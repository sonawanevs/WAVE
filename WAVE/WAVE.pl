#!/usr/bin/perl -wT
use strict;
use warnings;

use lib "modules"; 		# Specify the path of the directory where perl modules resides
use parseconfig;
use parselog;
use report;
use analyze;
use parsepayload;
use web;

print "\n";
print '##########################################################'."\n";
print '#		 _    _  ___  _   _ _____ 		 #'."\n";
print '#		| |  | |/ _ \| | | |  ___|		 #'."\n";
print '#		| |  | / /_\ \ | | | |__  		 #'."\n";
print '#		| |/\| |  _  | | | |  __| 		 #'."\n";
print '#		\  /\  / | | \ \_/ / |___ 		 #'."\n";
print '#		 \/  \/\_| |_/\___/\____/ 		 #'."\n";
print "#\t\t\t\t\t\t\t #\n";
print '#      Web Application Vulnerability analyzing Engine    #'."\n";
print '#		 	Version: 0.2 			 #'."\n";
print '#          mailto: sonawanevs@gmail.com	 #'."\n";
print '##########################################################'."\n\n";


my ($config_lookup, $logs_lookup, $is_secure, $domain_name, $logdir, $http_port, $custom_error_page, $auth_param, $login_page);
my ($oscmd_inj_payload, $urlredir_payload);
my (@exc_url);

#-- 1. Reading Configuration File....... # Calling Class file ParseConfig
$config_lookup = &parseconfig::readconfig();	# print (@{$config_lookup->{logfiles}});

	$oscmd_inj_payload = (${$config_lookup->{oscmd_inj_payload}});
	$urlredir_payload = (${$config_lookup->{urlredir_payload}});
	$is_secure = (${$config_lookup->{isSecure}});
	@exc_url = (@{$config_lookup->{exclude_url}});
	$domain_name = (${$config_lookup->{domain}});
	$logdir = (${$config_lookup->{log_dir}});
	$http_port = (${$config_lookup->{http_port}});
	$custom_error_page = (${$config_lookup->{custom_error_page}});	
	$login_page = (${$config_lookup->{login_page}});
	$auth_param = (${$config_lookup->{auth_param}});

#-- 2. Perform set of Operations on each log file
for my $logfile (@{$config_lookup->{logfiles}}) {

	# 3. Reading Log file....... # Calling Class file Parselog
	$logs_lookup = &parselog::readlogs($logfile, $domain_name, $logdir, @exc_url);	# print (@{$lookup->{response_body}}[1]);


	# 4. Generate/open HTML file for reporting
    &report::generate_HTML_page($logfile, ${$config_lookup->{report_dir}});


	# 5. Perform Attack
    for my $attack (@{$config_lookup->{attacks}}) {
	    if ($attack eq "xss") {
		 	print "\n* Started with XSS Attack\n";
		    &analyze::XSS_attack ($logs_lookup);
		 	print "  Finished with XSS Attack\n";
	    }
	    elsif ($attack eq "misc") {
	     	print "\n* Started with Miscellaneous Attacks\n";
      		&analyze::MISC_attack ($logs_lookup);
	     	print "  Finished with Miscellaneous Attacks\n";
		}
	    elsif ($attack eq "oscmd") {
	     	print "\n* Started with OS Command Injection Attack\n";
    #  		&analyze::OSCmd_attack ($oscmd_inj_payload, $logs_lookup, $is_secure);
	     	print "  Finished with OS Command Injection Attack\n";
		}
	    elsif ($attack eq "urlredir") {
	     	print "\n* Started with URL Redirection Attack\n";
     # 		&analyze::URLRedir_attack ($urlredir_payload, $logs_lookup, $is_secure);
	     	print "  Finished with URL Redirection Attack\n";
		}
	    elsif ($attack eq "deepurl") {
	     	print "\n* Started with Deep URL Access Attack\n";
      		&analyze::DeepURL_attack ($logs_lookup, $is_secure, $custom_error_page, $login_page, $auth_param);
	     	print "  Finished with Deep URL Access Attack\n";
		}
	    elsif ($attack eq "nossl") {
	     	print "\n* Started with noSSL Attack\n";
      		&analyze::SSL_attack ($logs_lookup, $is_secure, $http_port);
	     	print "  Finished with noSSL Attack\n";
		}
    }

	# 6. Close HTML Report file
    &report::close_HTML_page;

}
print "\n".'########################## END ##########################'."\n\n";
#END
