# wpscan
`WPScan` is a popular tool for scanning WordPress installations for vulnerabilities. It's included in Kali Linux and is used to identify security issues in WordPress sites.

### Installation

If WPScan is not already installed in your Kali Linux system, you can install it using:

```bash
sudo apt update
sudo apt install wpscan
```

### Basic Usage

The basic syntax for using WPScan is:

```bash
wpscan --url <target_url>
```

### Common Options

- `--url <target_url>`: Specifies the target WordPress site.
- `--enumerate <option>`: Enumerates users, plugins, or themes (e.g., `u` for users, `p` for plugins, `t` for themes).
- `--api-token <token>`: Use a WPScan API token for additional features.
- `--output <filename>`: Saves the output to a specified file.

### Examples and Output

1. **Basic Scan**

   To perform a basic scan on a WordPress site:

   ```bash
   wpscan --url https://example.com
   ```

   **Example Output:**

   ```
   WPScan - WordPress Security Scanner
   Version: 3.8.0
   ...
   [+] URL: https://example.com [197.254.1.1]
   [+] Started: 2025-02-26 08:00:00
   ...
   [+] Found 5 plugins:
      - akismet
      - jetpack
   ...
   [+] User Enumeration: 
      - admin
      - user1
   ...
   ```

2. **Enumerating Plugins**

   To enumerate plugins on a WordPress site:

   ```bash
   wpscan --url https://example.com --enumerate p
   ```

   **Example Output:**

   ```
   [+] Found 2 plugins:
      - akismet (Active)
      - jetpack (Inactive)
   ```

3. **Enumerating Users**

   To enumerate users:

   ```bash
   wpscan --url https://example.com --enumerate u
   ```

   **Example Output:**

   ```
   [+] User Enumeration:
      - admin
      - user1
   ```

4. **Saving Output to a File**

   To save the scan results to a file:

   ```bash
   wpscan --url https://example.com --output report.txt
   ```

### Notes

- Ensure you have permission to scan the target site to avoid legal issues.
- The effectiveness of WPScan depends on the configuration of the WordPress site and the plugins/themes in use.
- Regularly update WPScan for the latest vulnerability definitions.



               ALTERNATIVE
Wpscan is a popular WordPress security scanner tool included in Kali Linux. It helps identify vulnerabilities in WordPress installations, including plugins, themes, and core WordPress files.

### Installation

Wpscan is typically included in Kali Linux. If not, you can install it using the following command:

```bash
sudo apt-get install wpscan
```

### Usage

The basic syntax for using wpscan is:

```bash
wpscan -u <target_url>
```

Replace `<target_url>` with the URL of the WordPress installation you want to scan.

### Options

Some common options used with wpscan include:

* `-u <target_url>`: Specify the target URL.
* `--enumerate`: Enumerate users, plugins, and themes.
* `--enumerate-ap`: Enumerate all plugins and themes.
* `--enumerate-u`: Enumerate users.
* `--enumerate-t`: Enumerate themes.
* `--enumerate-p`: Enumerate plugins.
* `--version`: Display the wpscan version.
* `--help`: Display the help menu.

### Examples

1. **Basic Scan**

   To perform a basic scan of a WordPress installation, use the following command:

   ```bash
   wpscan -u http://example.com
   ```

   This will scan the WordPress installation at `http://example.com` and display the results.

2. **Enumerate Users, Plugins, and Themes**

   To enumerate users, plugins, and themes, use the following command:

   ```bash
   wpscan -u http://example.com --enumerate
   ```

   This will display a list of users, plugins, and themes used by the WordPress installation.

3. **Enumerate Plugins**

   To enumerate only plugins, use the following command:

   ```bash
   wpscan -u http://example.com --enumerate-p
   ```

   This will display a list of plugins used by the WordPress installation.

### Example Output

The output of wpscan will vary depending on the target WordPress installation and the options used. Here's an example output:

```
[+] URL: http://example.com
[+] Started: 2023-02-20 14:30:05

[+] Robots.txt available but allows all: http://example.com/robots.txt
[+] XML-RPC Interface available: http://example.com/xmlrpc.php
[+] WordPress version: 5.9.3
[+] WordPress theme: Twenty Twenty-Two version: 1.0
[+] WordPress plugins:
  [+] Akismet version: 4.2.3
  [+] Contact Form 7 version: 5.6.2
  [+] Jetpack version: 11.5

[+] Enumerating users...
  [+] User found: admin
  [+] User found: user1
  [+] User found: user2

[+] Finished: 2023-02-20 14:30:15
```

In this example, wpscan identified the WordPress version, theme, and plugins used by the installation. It also enumerated the users, including `admin`, `user1`, and `user2`.



                             ALTERNATIVE
Certainly, I'll provide information on using the WPScan tool in Kali Linux.

**WPScan - A WordPress Security Scanning Tool**

WPScan is a powerful command-line tool used to scan WordPress sites for security vulnerabilities and misconfigurations. It is included in the Kali Linux distribution.

**Installation**

WPScan is usually pre-installed in Kali Linux. If not, you can install it using the following command:

```
sudo apt-get update
sudo apt-get install wpscan
```

**Usage**

The basic syntax for using WPScan is:

```
wpscan [options] --url <target_wordpress_site>
```

**Common Options**

- `--url <target_wordpress_site>`: Specifies the URL of the WordPress site to scan.
- `--enumerate u` or `--enumerate users`: Enumerates WordPress user accounts.
- `--enumerate p` or `--enumerate passwords`: Attempts to brute-force WordPress user passwords.
- `--enumerate t` or `--enumerate themes`: Enumerates installed WordPress themes.
- `--enumerate p` or `--enumerate plugins`: Enumerates installed WordPress plugins.
- `--api-token <api_token>`: Provides an API token for the WPVulnDB API, which allows for more detailed scans.
- `-o <output_file>`: Saves the scan results to a specified output file.

**Examples**

1. **Basic Scan**

   To perform a basic scan on a WordPress site:

   ```
   wpscan --url https://example.com
   ```

   This will perform a basic scan and provide information about the WordPress installation, such as the version, installed plugins, and potential vulnerabilities.

2. **Enumerate Users**

   To enumerate the usernames of registered WordPress users:

   ```
   wpscan --url https://example.com --enumerate u
   ```

   This will attempt to identify valid WordPress user accounts.

3. **Brute-Force Passwords**

   To attempt to brute-force WordPress user passwords:

   ```
   wpscan --url https://example.com --enumerate u --enumerate p
   ```

   This will try to guess user passwords using a wordlist. Use this feature responsibly and only with permission.

4. **Enumerate Themes and Plugins**

   To list the installed WordPress themes and plugins:

   ```
   wpscan --url https://example.com --enumerate t
   wpscan --url https://example.com --enumerate p
   ```

   These commands will enumerate the installed themes and plugins, respectively.

**Example Output**

Here's an example of the output when running a basic scan on a WordPress site:

```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart

[+] URL: https://example.com/
[+] Started: Sun Feb 26 15:36:49 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://example.com/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress version 5.5.3 identified (Newest version: 5.6.2)
 | Found By: Emoji Settings (Passive Detection)
 | Confidence: 100%

[+] WordPress theme in use: twentytwentyone
 | Location: https://example.com/wp-content/themes/twentytwentyone/
 | Last Updated: 2023-01-31
 | Readme: https://example.com/wp-content/themes/twentytwentyone/README.txt
 | [!] The version is out of date, the latest version is 1.4
 | Found By: Css Style (Passive Detection)
 | Confidence: 90%

[+] 2 vulnerabilities identified:
 | [!] Title: WordPress 4.7-5.6.1 Authenticated Arbitrary File Deletion
 |     Fixed in: 5.6.2
 |     References:
 |      - https://wpscan.com/vulnerability/ee8d3f89-9400-4a45-a3a5-8b22a35e11db
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29447
 |      - https://blog.wpscan.com/wordpress/security/2021/03/25/wordpress-adoption-updates-against-recent-vulnerabilities.html
 |
 | [!] Title: WordPress 5.6.2 - 5.6.1 SQL Injection in $wpdb->prepare()
 |     Fixed in: 5.6.2
 |     References:
 |      - https://wpscan.com/vulnerability/ffa4befe-82c6-48bf-a404-f1d5eeacb5f0
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29450
 |      - https://blog.wpscan.com/wordpress/security/2021/03/25/wordpress-adoption-updates-against-recent-vulnerabilities.html

[+] Finished: Sun Feb 26 15:37:05 2023
[+] Requests Done: 19
[+] Cached Requests: 5
[+] Database Requests: 3
[+] Elapsed Time: 16.22 sec
```

This output provides information about the WordPress installation, including the version, installed theme, and identified vulnerabilities. The tool also attempts to enumerate users, themes, and plugins, and checks for known vulnerabilities.

Remember to use WPScan responsibly and only with permission on systems you are authorized to test.



                             ALTERNATIVE
`wpscan` is a popular, free, and open-source WordPress security scanner used to identify vulnerabilities in WordPress websites. It's a valuable tool for penetration testers and WordPress administrators alike. Here’s how to use it, with examples and expected outputs:

### Installation

`wpscan` is usually pre-installed in Kali Linux. If it's not, you can install it using:

```bash
sudo apt update
sudo apt install wpscan
```

You might also need to update the `wpscan` database to ensure you have the latest vulnerability definitions:

```bash
wpscan --update
```

### Basic Usage

The basic syntax for using `wpscan` is:

```bash
wpscan [options] --url <target URL>
```

### Common Options

*   `--url <target URL>`: Specifies the target WordPress site URL.
*   `--enumerate <option(s)>`: Enumerates various components such as plugins (`p`), themes (`t`), users (`u`), and configuration backups (`cfg`).
*   `--api-token <token>`: Uses an API token for enhanced scanning and enumeration (you can obtain a free token from WPScan).
*   `--passwords <path>`: Specifies a password list for brute-force attacks.
*   `--username <username>`: Specifies a single username for password brute-forcing.
*   `--usernames <path>`: Specifies a username list for enumeration or brute-forcing.
*   `--verbose`: Enables verbose output.
*   `--output <filename>`: Saves the output to a file.
*   `--random-user-agent`: Uses a random User-Agent for each request.
*   `--plugins-detection <mode>`: Specifies the plugin detection mode (e.g., `aggressive`, `passive`).

### Examples and Output

1.  **Basic Scan**

    To perform a basic scan on a WordPress site to identify the WordPress version and other basic information:

    ```bash
    wpscan --url example.com
    ```

    **Output:**

    ```
    [+] URL: https://example.com/ [172.217.160.142]
    [+] Started: Wed Feb 26 06:46:24 2025 UTC

    [+] WordPress version 5.8.1 identified (Insecure, release date: 2021-09-08).
     | See https://wpvulndb.com/vulnerabilities/12345
     |
     | Fixed in version 5.8.2

    [+] Interesting header: SERVER: Apache/2.4.41 (Ubuntu)

    [+] robots.txt found: https://example.com/robots.txt
     | Interesting entry: Disallow: /wp-admin/

    [+] Finished: Wed Feb 26 06:47:24 2025 UTC
    [+] Elapsed time: 1 minute
    ```

2.  **Enumerating Plugins**

    To enumerate installed plugins:

    ```bash
    wpscan --url example.com --enumerate p
    ```

    **Output:**

    ```
    [+] URL: https://example.com/ [172.217.160.142]
    [+] Started: Wed Feb 26 06:48:24 2025 UTC

    [+] WordPress version 5.8.1 identified (Insecure, release date: 2021-09-08).
     | See https://wpvulndb.com/vulnerabilities/12345
     |
     | Fixed in version 5.8.2

    [+] Enumerating installed plugins ...
     | Found plugin: akismet@4.1.7
     | Location: https://example.com/wp-content/plugins/akismet/
     | Last updated: 2020-12-08T16:17:11.000Z
     | Readme: https://example.com/wp-content/plugins/akismet/readme.txt
     |
     | Found plugin: jetpack@9.8
     | Location: https://example.com/wp-content/plugins/jetpack/
     | Last updated: 2021-09-21T10:51:01.000Z
     | Readme: https://example.com/wp-content/plugins/jetpack/readme.txt

    [+] Finished: Wed Feb 26 06:50:24 2025 UTC
    [+] Elapsed time: 2 minutes
    ```

3.  **Enumerating Themes**

    To enumerate installed themes:

    ```bash
    wpscan --url example.com --enumerate t
    ```

    **Output:**

    ```
    [+] URL: https://example.com/ [172.217.160.142]
    [+] Started: Wed Feb 26 06:51:24 2025 UTC

    [+] WordPress version 5.8.1 identified (Insecure, release date: 2021-09-08).

    [+] Enumerating installed themes ...
     | Found theme: twentytwentyone@1.3
     | Location: https://example.com/wp-content/themes/twentytwentyone/
     | Last updated: 2021-08-26T15:48:05.000Z
     | Readme: https://example.com/wp-content/themes/twentytwentyone/readme.txt

    [+] Finished: Wed Feb 26 06:52:24 2025 UTC
    [+] Elapsed time: 1 minute
    ```

4.  **Enumerating Users**

    To enumerate usernames:

    ```bash
    wpscan --url example.com --enumerate u
    ```

    **Output:**

    ```
    [+] URL: https://example.com/ [172.217.160.142]
    [+] Started: Wed Feb 26 06:53:24 2025 UTC

    [+] WordPress version 5.8.1 identified.

    [+] Enumerating users ...
     | Found Username: admin (ID: 1)
     | Found Username: editor (ID: 2)

    [+] Finished: Wed Feb 26 06:54:24 2025 UTC
    [+] Elapsed time: 1 minute
    ```

5.  **Brute-Force Attack**

    To perform a brute-force attack on a specific username:

    ```bash
    wpscan --url example.com --username admin --passwords /path/to/passwordlist.txt
    ```

    **Output:**

    ```
    [+] URL: https://example.com/ [172.217.160.142]
    [+] Started: Wed Feb 26 06:55:24 2025 UTC

    [+] WordPress version 5.8.1 identified.

    [+] Performing password brute-forcing for user 'admin'
         Trying password 'password123'
         Trying password 'admin123'
         [+] Password found: admin => secretpassword

    [+] Finished: Wed Feb 26 06:57:24 2025 UTC
    [+] Elapsed time: 2 minutes
    ```

6.  **Saving Output to a File**

    To save the scan results to a file:

    ```bash
    wpscan --url example.com --output report.txt
    ```

    This will save the output to a file named `report.txt`.

7.  **Using an API Token**

    To use an API token for more reliable scanning:

    ```bash
    wpscan --url example.com --api-token YOUR_API_TOKEN
    ```

### Notes

*   Ensure you have permission to scan the target to avoid legal issues.
*   The output can vary based on the target system's configuration and security measures.
*   Use `wpscan` responsibly and ethically.
*   Regularly update `wpscan` to ensure you have the latest vulnerability definitions.
*   Be aware that aggressive scanning or brute-force attacks can be detected and blocked by security measures.



                           ALTERNATIVE
`wpscan` is a popular tool included in Kali Linux that is used to scan WordPress installations for vulnerabilities. It is an open-source WordPress security scanner that helps identify issues such as weak passwords, outdated plugins, themes, and other security flaws.

### Installation
`wpscan` is usually pre-installed in Kali Linux. If it's not installed, you can install it using:

```bash
sudo apt update
sudo apt install wpscan
```

Alternatively, you can install it using Ruby:

```bash
sudo gem install wpscan
```

### API Key
To perform certain scans (e.g., plugin/theme enumeration), you need an API token for WPScan's vulnerability database. You can get a free API key by registering at the [WPScan website](https://wpscan.com).

Once you have the API key, you can configure it:

```bash
wpscan --api-token YOUR_API_TOKEN
```

### Basic Syntax
The general syntax for using `wpscan` is:

```bash
wpscan [options]
```

### Common Options
- **`--url <target>`**: Specifies the target WordPress site (required).
- **`--enumerate`**: Enumerates users, plugins, themes, etc. (e.g., `--enumerate u` for users, `--enumerate p` for plugins).
- **`--api-token`**: Provides your WPScan API token.
- **`--random-user-agent`**: Uses a random user agent to avoid detection.
- **`--passwords <file>`**: Specifies a password list for brute-forcing.
- **`--usernames <list>`**: Specifies usernames for brute-forcing.
- **`--force`**: Forces scanning even if the target URL is not detected as a WordPress site.
- **`--output <file>`**: Saves the output to a file.

---

### Examples and Outputs

#### 1. **Basic Scan**
To perform a simple scan of a WordPress site:

```bash
wpscan --url https://example.com
```

**Output:**

```
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

      WordPress Security Scanner by the WPScan Team
                         Version 3.8.21
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://example.com/ [192.0.2.1]
[+] Started: Tue Feb 26 08:00:00 2025

...

[+] WordPress version 5.8.3 identified (latest)
 | Found By: Meta Generator (HTML Tag)
 |  - https://example.com/, Match: 'WordPress 5.8.3'

[+] Enumerating plugins from passive detection ...
[+] Checking vulnerabilities against WPScan Vulnerability Database...

[+] Plugins identified:
 | plugin-name
 | Location: https://example.com/wp-content/plugins/plugin-name/
 | Last Updated: 2024-12-01
 | Vulnerabilities: CVE-2024-12345 (High)

[+] Scan Completed in 45 seconds
```

---

#### 2. **Enumerating Users**
To enumerate WordPress users:

```bash
wpscan --url https://example.com --enumerate u
```

**Output:**

```
[+] Enumerating WordPress Users ...
[+] Found User(s):
    [ID: 1, Name: admin, Login: admin]
    [ID: 2, Name: editor, Login: editor]
```

This information can be used for further attacks, such as brute-forcing passwords.

---

#### 3. **Enumerating Plugins**
To enumerate installed plugins and check for known vulnerabilities:

```bash
wpscan --url https://example.com --enumerate p --api-token YOUR_API_TOKEN
```

**Output:**

```
[+] Enumerating Plugins ...
[+] Plugins found:
 | plugin-name (1.2.3)
 | Location: https://example.com/wp-content/plugins/plugin-name/
 | Vulnerabilities: CVE-2024-56789 (High)
```

---

#### 4. **Brute-Forcing Passwords**
To brute-force the admin password, specify a username and a password list:

```bash
wpscan --url https://example.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

**Output:**

```
[+] Performing password attack on user 'admin' ...
[+] Found password for user 'admin': password123!
```

> **Note:** Ensure you have permission to test the target site to avoid legal consequences.

---

#### 5. **Saving Output to a File**
To save the scan results to a file:

```bash
wpscan --url https://example.com --output scan_report.txt
```

---

### Notes
- **Permission:** Always ensure you have explicit permission to scan a WordPress site.
- **Update Regularly:** Keep `wpscan` and its vulnerability database updated for accurate results.
- **Ethical Use:** Use `wpscan` responsibly and for authorized testing only.

By leveraging `wpscan`, you can identify vulnerabilities and misconfigurations in WordPress installations, helping to secure websites against potential attacks.





                                ALTERNATIVE
WPScan is a powerful tool included in Kali Linux that is specifically designed for scanning WordPress installations for vulnerabilities. It helps identify security issues related to plugins, themes, and the WordPress core itself.

### How to Use WPScan

1. **Installation**: WPScan is typically pre-installed in Kali Linux. If you need to install it, you can do so with the following command:
   ```bash
   sudo apt install wpscan
   ```

2. **Basic Command Structure**:
   The basic command to run WPScan is:
   ```bash
   wpscan --url <target_url>
   ```

3. **Common Options**:
   - `--url`: Specify the target WordPress site.
   - `-e`: Enumerate various components (e.g., plugins, themes).
   - `--api-token`: Use this to access the WPScan Vulnerability Database for detailed vulnerability information.
   - `--output`: Save the results to a specified file.
   - `--help`: Display help information for additional options.

### Examples

1. **Basic Scan**:
   To perform a basic scan on a WordPress site, use:
   ```bash
   wpscan --url http://example.com
   ```
   This command will scan the specified URL and provide information about the WordPress version, plugins, themes, and any vulnerabilities found.

2. **Enumerating Plugins**:
   To enumerate installed plugins, you can use:
   ```bash
   wpscan --url http://example.com --enumerate p
   ```
   This will list all plugins installed on the target site, along with their versions.

3. **Checking for Vulnerable Plugins**:
   To check for vulnerable plugins using the WPScan API, run:
   ```bash
   wpscan --url http://example.com -e vp --api-token YOUR_API_TOKEN
   ```
   Replace `YOUR_API_TOKEN` with your actual API token. This command will provide detailed information about any known vulnerabilities in the plugins.

4. **User Enumeration**:
   To enumerate users on the WordPress site, use:
   ```bash
   wpscan --url http://example.com -e u
   ```
   This will attempt to identify usernames that could be targeted for brute-force attacks.

### Example Output

When you run a scan, the output might look something like this:

```
_______________________________________________________________
__ _______ _____
\ \ / / __ \ / ____|
\ \ /\ / /| |__) | (___ ___ __ _ _ __
\ \/ \/ / | ___/ \___ \ / __|/ _` | '_ \
\ /\ / | | ____) | (__| (_| | | | |
\/ \/ |_| |_____/ \___|\__,_|_| |_|
WordPress Security Scanner by the WPScan Team
Version 3.8.27
_______________________________________________________________

[+] URL: http://example.com
[+] Started: Mon Feb 26 14:07:40 2025
[+] WordPress version 5.8.1 identified
[+] Enumerating installed plugins ...
[+] We found 5 plugins:
   - akismet (4.1.9)
   - jetpack (10.0)
   - wpforms-lite (1.6.6)
   - contact-form-7 (5.4.1)
   - really-simple-ssl (5.2.0)

[+] Checking for vulnerabilities...
[+] Vulnerable plugins found:
   - wpforms-lite (1.6.6) - CVE-2021-12345
```

This output provides a summary of the scan, including the WordPress version, installed plugins, and any vulnerabilities detected.

### Conclusion

WPScan is an essential tool for anyone managing WordPress sites, allowing for proactive security assessments and vulnerability management. By regularly scanning your WordPress installations, you can identify and mitigate potential security risks effectively.

---
Learn more:
1. [wpscan | Kali Linux Tools](https://www.kali.org/tools/wpscan/)
2. [WPScan Intro: How to Scan for WordPress Vulnerabilities](https://blog.sucuri.net/2023/12/wpscan-intro-how-to-scan-for-wordpress-vulnerabilities.html)
3. [How to Use wpscan in Kali Linux? - GeeksforGeeks](https://www.geeksforgeeks.org/how-to-use-wpscan-in-kali-linux/)
