'''
"many eyes" is a quick and dirty, multi-threaded program to scrape data from
multiple OSINT sources. This is cross platform however has zero exception handling 
for windows as windows sucks. I wrote this to teach interns and analysts at KPMG on 
how to collect relevant data automagically with python from public sources as part
of the infosec training. 

many-eyes reads data from terms.txt and outputs intel as nice json dumps. Before running 
it, configure your api keys in config.py.

The public release contains only twitter and shodan integration however internally, multiple 
other systems like censys, facebook, virustotal et al are supported.

The program is quite modular, and can be extended easily by adding relevant service code 
and configurations in respective files. 

Performance wise it is just okay, can be tuned a lot and probably will have a lot of bugs.

In case of issues, reach out to admin@theprohack.com
'''

from multiprocessing import Process
from twarc import Twarc
import json, fileinput, sys, shodan, config

twitter_auth = Twarc(config.consumer_key, config.consumer_secret, config.access_token, config.access_token_secret)
shodan_auth = shodan.Shodan(config.shodan_api_key)

with open('terms.txt','r') as query_terms_file_content:
	my_query_terms = [line.strip() for line in query_terms_file_content]


# Twitter Querying Function

def twitter_query_function():
	print ("	[TWITTER]	Loading twitter search terms")
	if len(my_query_terms) > 0:
		twitter_query = ",".join(my_query_terms)
		print ("	[TWITTER]	Parsing search terms!")
		print ("	[TWITTER]	Querying following search terms: " + twitter_query)
	
		for tweet in twitter_auth.filter(track = twitter_query):
			with open('twitter_data.json', 'a') as json_twitter_output_file:
				json.dump(tweet, json_twitter_output_file, indent=4, sort_keys=True)
				print ("	[TWITTER]	Twitter authentication successful, dumping results")
	else:
		print ("	[TWITTER]	No search terms provided, printing generic stream")
		for tweet in twarc.sample():
			print(tweet)
	json_twitter_output_file.close()


# Shodan Querying Function

def shodan_query_function():
	print ("	[SHODAN]	Loading shodan search terms")
	if len(my_query_terms) > 0:
		
		shodan_query = "\n".join(my_query_terms)
		shodan_query_print = ",".join(my_query_terms)
		print ("	[SHODAN]	Parsing search terms!")
		print ("	[SHODAN]	Querying following search terms: "+ shodan_query_print)
		for shodan_query in my_query_terms:
			shodan_query_output = shodan_auth.search(shodan_query)
			with open('shodan_data.json', 'a') as json_shodan_output_file:
				json.dump(shodan_query_output, json_shodan_output_file, indent=4, sort_keys=True)
		print ("	[SHODAN]	Shodan authentication successful, dumping results")
		

	else:
			print ("	[SHODAN]	No search terms provided!")
	json_shodan_output_file.close()


# For debug and tshoot, comment out process functions from here
	
if __name__=='__main__':
    try:
     p1 = Process(target = twitter_query_function)
     p1.start()
     p2 = Process(target = shodan_query_function)
     p2.start()
    except KeyboardInterrupt:
        print ' #	Caught Interrupt! Exiting..'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
	'''
	PS : I did try implementing exception handling in vain, then I read this
	https://stackoverflow.com/questions/35772001/how-to-handle-the-signal-in-python-on-windows-machine
	and thought it was too much work writing stuff in windows
	'''
	
query_terms_file_content.close()