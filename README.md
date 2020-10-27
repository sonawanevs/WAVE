# WAVE
WAVE - Web Application Vulnerability Scanner Enginer

"WAVE - Web Application Vulnerability analysis Engine" is the web application vulnerability assessment tool. The intention to write this tool is to ease an application security engineer in its manual testing process. Mostly in case of performing application security assessment on Production server. The very first release works on the determination of the Non-Persistent XSS injection points. Tool determines the parameters which are getting reflected in the response and generates the report.


WORKING:-
Tool reads log file generated with the help of famous web proxy "BurpSuite". We have released the customised version of BurpSuite Web Proxy. Pentester will be using this customised BurpSuite proxy to generate log files. The WAVE will analyse these logs. It makes use of configuration file "configuration.txt" to get important parameters like log file names, Attacks to be performed and web pages that needs to be excluded from testing. An application tester need to update ""Configuration.txt" file. After validating all the data in the configuration file, the tool starts analyzing the vulnerabilities. The tool updates you about the current running task. After successful execution, it generated the HTML reports.


IMP: Please follow the instructions provided in the "Instructions.txt" file before running the tool.


SUPPORT:
Please report all the bugs in the present code @ sonawanevs@gmail.com


I think the tool is useful for pen-testers, to easily find out what's vulnerabilities are present in the application mostly by analysing the logs files.

cheers,
Vaibhav Sonawane
