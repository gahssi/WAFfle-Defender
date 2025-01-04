# WAFfle Defender

### Project details

View the slide deck [here](https://1sfu-my.sharepoint.com/:b:/g/personal/aya119_sfu_ca/EQb7P26F3B5Pj_14_Uc-230BHhz4KD_CoB6tkhUJcGyREg?e=sAmDza).

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

Navigate to `/var/www/html` in the Kali VM (`waffle_rnd.ova`) to find the following files/directories:
- `analysis_layer.py` and `analysis_layer.log`
- `rule_updater.py` and `rule_updator.log`
- `regex_rules.txt`
- `injection.tmp`
- `dvwa/..` (contains the DVWA web app code)
- `test_files/..` (contains a couple test scripts)

The updated Apache config is saved in `/etc/apache2/sites-available/000-default.conf`.

Whenever you reboot the VM, ensure you start up the Apache webserver and DVWA backend services (MySQL/PHP):
```bash
sudo service apache2 start
sudo dvwa-start
```

Whenever modifying `000-default.conf`, ensure you restart Apache afterwards to apply the changes. If troubleshooting other issues, reviewing the Apache service status may help:
```bash
sudo service apache2 restart
sudo service apache2 status
```

Run all scripts as root:
```bash
sudo su
cd /var/www/html
python3 analysis_layer.py
python3 rule_updater.py # only need to run this for async version
```

Open the SQLi test page `http://localhost/dvwa/vulnerabilities/sqli` via a browser.

If you double-click the input field on the test page, you should see a drop-down menu with multiple pre-saved SQLis.

To verify ModSecurity and the layer are working:
- submit a SQLi that ModSec blocks (e.g. `' or '1'='1'`) -> redirects to 403 Forbidden page
- submit a SQLi that bypasses ModSec but the analysis layer blocks (e.g. `MIN(%20delay%20'0:20'%20-- for = "sql injection detection"`) -> redirects to different 403 Forbidden page 
- submit a safe (e.g. `bob`) or unknown input -> not redirected to 403 Forbidden page

You can clear `regex_rules.txt` and `injection.tmp` to restart the analysis layer to a fresh state (do not delete them). You can also clear the generated logs to help reduce the amount of information to read through when debugging/validating results. 
```bash
echo -n > regex_rules.txt && echo -n > injection.tmp
echo -n > rule_updater.log && echo -n > analysis_layer.log
```

A couple other Apache logs worth inspecting:
- `/var/log/apache2/error.log`
- `/var/log/apache2/access.log`
- `/var/log/apache2/modsec_audit.log`

Note: Ensure you set a shell environment variable for your GPT API key before running the analysis layer (if using GPT):
```bash
export OPENAI_API_KEY='<api_key_here>'
```

### TODOs (for way into the future) 
- Make analysis layer compatible with other WAFs (including webservers beyond Apache)
- Make a shell script to simplify installation and configuration process for all required components

