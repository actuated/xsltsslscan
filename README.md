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
* New `*no-style*` and `*no-style-no-color*` versions exist for copying and pasting into picky rich text reporting tools. These tables have no table or font styles to them (borders, background colors, etc.), with the exception that one still has the orange and red highlighting for bad results.
