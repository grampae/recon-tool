# recon-tool
Takes a list of urls (from httpx or wherever) and grabs 
- screenshots
- wappalyzer tech info
- does some semgrep like cursory matching for possible avenues to look in to.
 
After this it uses Jinja to create a html page of all of this info to browse through quickly during a large engagement to determine where you want to spend your time.  
 
Screenshots etc are stored in the project folder that you specify at command execution.
