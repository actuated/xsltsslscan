# xsltsslscan
XSLT for SSLScan 2.0 XML results

# Usage
```
xsltproc xsltsslscan[version].xsl [SSLScan XML file] > [HTML output file]
```
* Creates an HTML file with three tables:
  - Findings: A table with findings and the applicable hosts/results.
  - Ciphers: A table of targets and accepted ciphers, with "bad" ciphers colorized.
  - Full: A table with targets, enabled/disabled protocols, server checks, accepted ciphers, key exchange groups, server signature algorithms, and certificate checks.
  
# Notes
* There's currently an extraneous space in the certificate signature algorithm field in the full report, coming from leading spaces in the XML object value. This is pending some certificate XML changes in newer versions, will have to update later or make different XSLTs for different versions.
