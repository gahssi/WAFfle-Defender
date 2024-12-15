# WAFfle Defender

### Project details

Link to repo: https://github.com/gahssi/WAFfle-Defender

Final submission for CMPT 782 R&D Project, developed by:  
*Alexander Yemane*  
*William Fung*  
*Jerry Wang*  

Supervised by:  
*Prof. Mohammad Tayebi*

And in collaboration with:  
*AI-Driven Cybersecurity research group at SFU*

---

### Instructions

The Kali VM snapshot (waffle_rnd.ova) should contain the following components in `/var/www/html`:
- DVWA (saved in `dvwa` directory)
- analysis_layer.py and analysis_layer.log
- rule_updater.py and rule_updator.log
- regex_rules.txt
- injection.tmp
- a couple test scripts (saved in `test_files` directory)

The updated Apache config is saved in `/etc/apache2/sites-available/000-default.conf`.

By default, the Apache webserver, DVWA backend services (e.g. MySQL/PHP), and ModSec rule engine should be on. After rebooting the VM, make sure to start them up again.
```bash
sudo service apache2 start
sudo dvwa-start
```

Whenver modifying 000-default.conf, make sure to restart Apache afterwads to apply the changes. If you experience general issues with Apache, restarting and viewing its status usually helps.
```bash
sudo service apache2 restart
sudo service apache2 status
```

If you make changes to the analysis layer scripts, make sure to close any currently running instances before rerunning them.

Run all scripts as root.
```bash
sudo su
cd /var/www/html
python3 analysis_layer.py
python3 rule_updater.py # only need to run this for async version
```

You can open the localhosted SQLI test page at http://localhost/dvwa/vulnerabilities/sqli.

If you double-click the input field on the DVWA SQLi test page, you should see a drop-down menu with multiple pre-saved SQL injections.

To verify the layer is working:
- submit a SQL injection that ModSec blocks (e.g. `' or '1'='1'`) -> redirected to 403 Forbidden page by ModSec
- submit a SQL injection that bypasses ModSec but the analysis layer blocks (e.g. `MIN(%20delay%20'0:20'%20-- for = "sql injection detection"`) -> redirected to different 403 Forbidden page by analysis layer 
- submit a safe (e.g. `bob`) or unknown input -> not redirected to 403 Forbidden page

You can clear regex_rules.txt and injection.tmp to restart the analysis layer to a fresh state (do not delete them). You can also clear the logs generated from the layer to help reduce the amount of information to read through when validating results. 
```bash
echo -n > rule_updater.log && echo -n > analysis_layer.log
echo -n > regex_rules.txt && echo -n > injection.tmp
```

A couple other Apache logs worth inspecting:
- /var/log/apache2/error.log
- /var/log/apache2/access.log
- /var/log/apache2/modsec_audit.log

Note: Make sure to set an environment variable in your VM for your GPT API key before running the analysis layer scripts (if using the updated versions).
```bash
export OPENAI_API_KEY='<api_key_here>'
```

### TODOs (for way into the future) 
- Figure out how to make analysis layer compatible with other WAFs (ModSecurity 2.x is an Apache module, others may be standalone or may not be Apache-based)
- Make a shell script to simplify installation and configuration process

