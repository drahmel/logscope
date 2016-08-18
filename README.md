# logscope
Log Scope is a simple Apache access log analysis tool that lets you output log information based on restricted criteria.


Log Scope will let you filter Apache log files based on criteria such as IP address or date/time

Log Scope is a simple Apache access log analysis tool that lets you output log information based on restricted criteria. For example:

Display all of the log entries for the IP address 127.0.0.1
List all access entries that occurred between 1:27:10 and 1:28:15
List of all of requests for the file mypage.html

Examples of usage:

python logscope.py c:\access.log --ip 127.0.0.1 -b2008,9,17,12,30,0
python logscope.py c:\access.log --text get_data
python logscope.py c:\access.log --ip 127.0.0.2 logscope.py c:\access.log --resp 404
logscope.py c:\access.log,c:\access2.log,c:\access3.log --resp 404
logscope.py c:\access.log -b2008,7,3,8,30,0 -e2008,7,3,14,30,0
logscope.py c:\access.log -b2008,7,3,8,30,0 -e2008,7,3,14,30,0 -t css
logscope.py c:\logfilter.txt -t process_card
logscope.py c:\logfilter.txt -t add_member_account
logscope.py c:\logfilter.txt -i 204.108.100.244 -o c:\session_jddavid18.log

