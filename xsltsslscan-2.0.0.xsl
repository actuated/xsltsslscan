<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<html>
<!--
XSLTSSLScan
XSLT file for SSLScan 2.0 XML results
Ted R (github: actuated)
Created 6/30/2020, Last Modified 7/2/2020

07/02/2020 - RE: Issue #1, added key exchange group and server signature algorithm checks, including 0xfdff.
08/19/2020 - Modified Findings Table SSL2/3 and TLS1.0 lists to list hosts and not ciphers. Takes up less space, but mostly because sslscan doesn't currently report accepted SSL2/3 ciphers.
-->
<head>
  <title>XSLTSSLScan</title>
  <style>
  body {font-family: sans-serif;
    font-size: small;}
  a {color: #34a1eb;}
  a:hover {color: blue;}
  table, td, th {border: 1px solid black;
    border-collapse: collapse;
    font-size: small;}
  th {text-align: left;
    background-color: #34a1eb;}
  td {vertical-align: top;}
  .risk1 {color: black;}
  .risk2 {color: #eb8634;}
  .risk3 {color: red;}
  fieldset {display: inline-block;}
  </style>
</head>
<body>

  <b><font size="+1">XSLTSSLScan</font> - by <a href="https://github.com/actuated" target="_new">actuated</a> - for parsing <a href="https://github.com/rbsec/sslscan" target="_new">SSLScan</a> XML results</b><br/><br/>

  <fieldset><legend>Contents</legend>
  <a href="#findings">Table 1: Findings</a><br/>
  <a href="#ciphers">Table 2: Accepted Ciphers per Target</a><br/>
  <a href="#full">Table 3: Full Results per Target</a><br/>
  </fieldset><br/><br/>

<!--Begin Findings Table-->
  <a name="findings"></a><b><font size="+1">Table 1: Findings</font></b><br/>
  <table>
    <!--Heading Row-->
    <tr>
      <th>Finding</th>
      <th>Results</th>
    </tr>

    <!--Report Insecure Session Renegotiation-->
    <tr><td>Insecure Session Renegotiation</td><td>
    <xsl:for-each select="document/ssltest/renegotiation">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
      <xsl:if test="(./@supported = '1') and (./@secure = '0')">
        <xsl:value-of select="concat(../@host,':',../@port)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report Insecure Session Renegotiation-->
    <tr><td>Compression Enabled</td><td>
    <xsl:for-each select="document/ssltest/compression">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
      <xsl:if test="(./@supported = '1')">
        <xsl:value-of select="concat(../@host,':',../@port)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report Heartbleed-->
    <tr><td>Vulnerable to Heartbleed</td><td>
    <xsl:for-each select="document/ssltest/heartbleed">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
      <xsl:if test="(./@vulnerable = '1')">
        <xsl:value-of select="concat(../@host,':',../@port,' - ',./@sslversion)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report SSLv2-->
    <tr><td>SSLv2 Enabled</td><td>
    <xsl:for-each select="document/ssltest/protocol">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
      <xsl:if test="((./@type = 'ssl') and (./@version = '2') and (./@enabled = '1'))">
        <xsl:value-of select="concat(../@host,':',../@port)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report SSLv3-->
    <tr><td>SSLv3 Ciphers</td><td>
    <xsl:for-each select="document/ssltest/protocol">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
      <xsl:if test="((./@type = 'ssl') and (./@version = '3') and (./@enabled = '1'))">
        <xsl:value-of select="concat(../@host,':',../@port)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report TLSv1.0-->
    <tr><td>TLSv1.0 Enabled</td><td>
    <xsl:for-each select="document/ssltest/protocol">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
      <xsl:if test="((./@type = 'tls') and (./@version = '1.0') and (./@enabled = '1'))">
        <xsl:value-of select="concat(../@host,':',../@port)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report <128-bit Ciphers for TLSv1.1+-->
    <tr><td>TLSv1.1+ &lt;128-bit Ciphers</td><td>
    <xsl:for-each select="document/ssltest/cipher">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
         <xsl:sort select="./@sslversion" order="descending"/>
         <xsl:sort select="./@bits" order="descending"/>
         <xsl:sort select="./@cipher" order="descending"/>
      <xsl:if test="((./@sslversion = 'TLSv1.1') or (./@sslversion = 'TLSv1.2') or (./@sslversion = 'TLSv1.3')) and (./@bits &lt; '128')">
          <xsl:value-of select="concat(../@host,':',../@port,' - ',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report RC4 Ciphers for TLSv1.1+-->
    <tr><td>TLSv1.1+ RC4 Ciphers</td><td>
    <xsl:for-each select="document/ssltest/cipher">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
         <xsl:sort select="./@sslversion" order="descending"/>
         <xsl:sort select="./@bits" order="descending"/>
         <xsl:sort select="./@cipher" order="descending"/>
      <xsl:if test="((./@sslversion = 'TLSv1.1') or (./@sslversion = 'TLSv1.2') or (./@sslversion = 'TLSv1.3')) and contains(./@cipher,'RC4')">
          <xsl:value-of select="concat(../@host,':',../@port,' - ',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report Anonymous Ciphers for TLSv1.1+-->
    <tr><td>TLSv1.1+ Anonymous Ciphers</td><td>
    <xsl:for-each select="document/ssltest/cipher">
         <!--Set Order-->
         <xsl:sort select="../@host" order="ascending"/>
         <xsl:sort select="../@port" order="ascending"/>
         <xsl:sort select="./@sslversion" order="descending"/>
         <xsl:sort select="./@bits" order="descending"/>
         <xsl:sort select="./@cipher" order="descending"/>
      <xsl:if test="((./@sslversion = 'TLSv1.1') or (./@sslversion = 'TLSv1.2') or (./@sslversion = 'TLSv1.3')) and (contains(./@cipher,'AHD') or contains(./@cipher,'AECDH'))">
          <xsl:value-of select="concat(../@host,':',../@port,' - ',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report Self-Signed Certificates-->
    <tr><td>Detected Self-Signed Certificates</td><td>
    <xsl:for-each select="document/ssltest/certificates/certificate">
         <!--Set Order-->
         <xsl:sort select="../../@host" order="ascending"/>
         <xsl:sort select="../../@port" order="ascending"/>
      <xsl:if test="(./self-signed = 'true')">
        <xsl:value-of select="concat(../../@host,':',../../@port,' - Subject: ',./subject,', Issuer: ',./issuer)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report Expired Certificates-->
    <tr><td>Expired Certificates</td><td>
    <xsl:for-each select="document/ssltest/certificates/certificate">
         <!--Set Order-->
         <xsl:sort select="../../@host" order="ascending"/>
         <xsl:sort select="../../@port" order="ascending"/>
      <xsl:if test="(./expired = 'true')">
        <xsl:value-of select="concat(../../@host,':',../../@port,' - Invalid After: ',./not-valid-after)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report Weak Certificate Signature Algorithms-->
    <tr><td>Weak Certificate Signature Algorithms</td><td>
    <xsl:for-each select="document/ssltest/certificates/certificate">
         <!--Set Order-->
         <xsl:sort select="../../@host" order="ascending"/>
         <xsl:sort select="../../@port" order="ascending"/>
      <xsl:if test="contains(./signature-algorithm,'sha1') or contains(./signature-algorithm,'md5')">
        <xsl:value-of select="concat(../../@host,':',../../@port,' -',./signature-algorithm)"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

    <!--Report Weak Certificate RSA Keys-->
    <tr><td>Weak Certificate RSA Keys</td><td>
    <xsl:for-each select="document/ssltest/certificates/certificate">
         <!--Set Order-->
         <xsl:sort select="../../@host" order="ascending"/>
         <xsl:sort select="../../@port" order="ascending"/>
      <xsl:if test="./pk/@bits &lt; 2048">
        <xsl:value-of select="concat(../../@host,':',../../@port,' -',./pk/@bits,' bits')"/><br/>
      </xsl:if>
    </xsl:for-each>
    </td></tr>

  </table>
<!--End Findings Table-->

<br/>

<!--Begin Ciphers Table-->
  <a name="ciphers"></a><b><font size="+1">Table 2: Accepted Ciphers per Target</font></b><br/>
  <table>
    <!--Heading Row-->
    <tr>
      <th>Target</th>
      <th>Accepted Ciphers</th>
    </tr>
    <!--Per-SSLScan Result Row Template-->
    <xsl:for-each select="document/ssltest">
    <xsl:sort select="./@host" order="ascending"/>
    <tr>

      <td><!--Host Cell-->
        <xsl:value-of select="concat(./@host,':',./@port)"/>
      </td>

     <td><!--Ciphers Cell-->
       <xsl:for-each select="./cipher">
         <!--Set Order-->
         <xsl:sort select="./@sslversion" order="descending"/>
         <xsl:sort select="./@bits" order="descending"/>
         <xsl:sort select="./@cipher" order="descending"/>
         <!--Check Accepted and Preferred Ciphers-->
         <xsl:if test="(./@status = 'accepted') or (./@status = 'preferred')">
           <xsl:choose>
             <!--Find and Check Ciphers with DHE-->
             <xsl:when test="./@dhebits">
                <!--Check if SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(contains(./@sslversion,'SSL')) or (./@sslversion = 'TLSv1.0') or (./@bits &lt; '128') or (contains(./@cipher,'RC4')) or (contains(./@cipher,'AHD')) or (contains(./@cipher,'AECDH'))">
                  <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_DHE-',./@dhebits,'-bits')"/></font><br/>
                </xsl:if>
                <!--Check if TLSv1.1 or <2048 DHE bits, and not SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="((./sslversion = 'TLSv1.1') or (./@dhebits &lt; '2048')) and (not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH')))">
                  <font class="risk2"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_DHE-',./@dhebits,'-bits')"/></font><br/>
                </xsl:if>
                <!--Check if not SSL, TLSv1.0, TLSv1.1, <128 bits, RC4, AHD, AECDH, <2048 DHE bits-->
                <xsl:if test="not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@sslversion = 'TLSv1.1') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH')) and not(./@dhebits &lt; '2048')">
                  <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_DHE-',./@dhebits,'-bits')"/></font><br/>
                </xsl:if>
             </xsl:when>
            </xsl:choose>
            <xsl:choose>
              <!--Find and Check Ciphers with Curve-->
              <xsl:when test="./@ecdhebits">
                <!--Check if SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(contains(./@sslversion,'SSL')) or (./@sslversion = 'TLSv1.0') or (./@bits &lt; '128') or (contains(./@cipher,'RC4')) or (contains(./@cipher,'AHD')) or (contains(./@cipher,'AECDH'))">
                  <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_Curve-',./@curve,'-DHE-',./@ecdhebits)"/></font><br/>
                </xsl:if>
                <!--Check if TLSv1.1 and not SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(./sslversion = 'TLSv1.1') and not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH'))">
                  <font class="risk2"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_Curve-',./@curve,'-DHE-',./@ecdhebits)"/></font><br/>
                </xsl:if>
                <!--Check if not SSL, TLSv1.0, TLSv1.1, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@sslversion = 'TLSv1.1') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH'))">
                  <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_Curve-',./@curve,'-DHE-',./@ecdhebits)"/></font><br/>
                </xsl:if>
              </xsl:when>
            </xsl:choose>
            <xsl:choose>
              <!--Check Ciphers without DHE or Curve-->
              <xsl:when test="not(./@dhebits) and not(./@ecdhebits)">
                <!--Check if SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(contains(./@sslversion,'SSL')) or (./@sslversion = 'TLSv1.0') or (./@bits &lt; '128') or (contains(./@cipher,'RC4')) or (contains(./@cipher,'AHD')) or (contains(./@cipher,'AECDH'))">
                  <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/></font><br/>
                </xsl:if>
                <!--Check if TLSv1.1 and not SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(./sslversion = 'TLSv1.1') and not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH'))">
                  <font class="risk2"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/></font><br/>
                </xsl:if>
                <!--Check if not SSL, TLSv1.0, TLSv1.1, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@sslversion = 'TLSv1.1') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH'))">
                  <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/></font><br/>
                </xsl:if>
              </xsl:when>
            </xsl:choose>
          </xsl:if>
        </xsl:for-each>
      </td>

    </tr>
    </xsl:for-each>
  </table>
<!--End Ciphers Table-->

<br/>

<!--Begin Full Results Table-->
  <a name="full"></a><b><font size="+1">Table 3: Full Results per Target</font></b><br/>
  <table>
    <!--Heading Row-->
    <tr>
      <th>Target</th>
      <th>Server Protocols</th>
      <th>Server Checks</th>
      <th>Accepted Ciphers</th>
      <th>Key Exchange Groups</th>
      <th>Server Signature Algorithms</th>
      <th>Certificate Checks</th>
    </tr>
    <!--Per-SSLScan Result Row Template-->
    <xsl:for-each select="document/ssltest">
    <xsl:sort select="./@host" order="ascending"/>
    <tr>

      <td><!--Host Cell-->
        <xsl:value-of select="concat(./@host,':',./@port)"/>
      </td>

      <td><!--Protocol Cell-->
        <xsl:for-each select="./protocol">
          <xsl:if test="((./@type = 'ssl') and (./@version = '2') and (./@enabled = '1'))">
            <font class="risk3"><xsl:value-of select="concat('-',./@type,' ',./@version,' enabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'ssl') and (./@version = '2') and (./@enabled = '0'))">
            <font class="risk1"><xsl:value-of select="concat('-',./@type,' ',./@version,' disabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'ssl') and (./@version = '3') and (./@enabled = '1'))">
            <font class="risk3"><xsl:value-of select="concat('-',./@type,' ',./@version,' enabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'ssl') and (./@version = '3') and (./@enabled = '0'))">
            <font class="risk1"><xsl:value-of select="concat('-',./@type,' ',./@version,' disabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'tls') and (./@version = '1.0') and (./@enabled = '1'))">
            <font class="risk3"><xsl:value-of select="concat('-',./@type,' ',./@version,' enabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'tls') and (./@version = '1.0') and (./@enabled = '0'))">
            <font class="risk1"><xsl:value-of select="concat('-',./@type,' ',./@version,' disabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'tls') and (./@version = '1.1') and (./@enabled = '1'))">
            <font class="risk2"><xsl:value-of select="concat('-',./@type,' ',./@version,' enabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'tls') and (./@version = '1.1') and (./@enabled = '0'))">
            <font class="risk1"><xsl:value-of select="concat('-',./@type,' ',./@version,' disabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'tls') and (./@version = '1.2') and (./@enabled = '1'))">
            <font class="risk1"><xsl:value-of select="concat('-',./@type,' ',./@version,' enabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'tls') and (./@version = '1.2') and (./@enabled = '0'))">
            <font class="risk2"><xsl:value-of select="concat('-',./@type,' ',./@version,' disabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'tls') and (./@version = '1.3') and (./@enabled = '1'))">
            <font class="risk1"><xsl:value-of select="concat('-',./@type,' ',./@version,' enabled')"/></font><br/>
          </xsl:if>
          <xsl:if test="((./@type = 'tls') and (./@version = '1.3') and (./@enabled = '0'))">
            <font class="risk2"><xsl:value-of select="concat('-',./@type,' ',./@version,' disabled')"/></font><br/>
          </xsl:if>
        </xsl:for-each>
      </td>

     <td><!--Server Checks Cell-->
       <!--Check Session Renegotiaion-->
       <xsl:if test="./renegotiation/@supported = '0'">
         <font class="risk1">-Session renegotiation not supported</font><br/>
       </xsl:if>
       <xsl:if test="((./renegotiation/@supported = '1') and (./renegotiation/@secure = '1'))">
         <font class="risk1">-Secure session renegotiation supported</font><br/>
       </xsl:if>
       <xsl:if test="((./renegotiation/@supported = '1') and (./renegotiation/@secure = '0'))">
         <font class="risk3">-Insecure session renegotiation supported</font><br/>
       </xsl:if>
       <!--Check Compression-->
       <xsl:if test="./compression/@supported = '0'">
         <font class="risk1">-Compression disabled</font><br/>
       </xsl:if>
       <xsl:if test="./compression/@supported = '1'">
         <font class="risk3">-Compression enabled</font><br/>
       </xsl:if>
       <!--Check Heartbleed-->
       <xsl:for-each select="./heartbleed">
         <xsl:if test="./@vulnerable = '1'">
           <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,' vulnerable to Heartbleed')"/></font><br/>
         </xsl:if>
         <xsl:if test="./@vulnerable = '0'">
           <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,' not vulnerable to Heartbleed')"/></font><br/>
         </xsl:if>
       </xsl:for-each>
     </td>

     <td><!--Ciphers Cell-->
       <xsl:for-each select="./cipher">
         <!--Set Order-->
         <xsl:sort select="./@sslversion" order="descending"/>
         <xsl:sort select="./@bits" order="descending"/>
         <xsl:sort select="./@cipher" order="descending"/>
         <!--Check Accepted and Preferred Ciphers-->
         <xsl:if test="(./@status = 'accepted') or (./@status = 'preferred')">
           <xsl:choose>
             <!--Find and Check Ciphers with DHE-->
             <xsl:when test="./@dhebits">
                <!--Check if SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(contains(./@sslversion,'SSL')) or (./@sslversion = 'TLSv1.0') or (./@bits &lt; '128') or (contains(./@cipher,'RC4')) or (contains(./@cipher,'AHD')) or (contains(./@cipher,'AECDH'))">
                  <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_DHE-',./@dhebits,'-bits')"/></font><br/>
                </xsl:if>
                <!--Check if TLSv1.1 or <2048 DHE bits, and not SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="((./sslversion = 'TLSv1.1') or (./@dhebits &lt; '2048')) and (not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH')))">
                  <font class="risk2"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_DHE-',./@dhebits,'-bits')"/></font><br/>
                </xsl:if>
                <!--Check if not SSL, TLSv1.0, TLSv1.1, <128 bits, RC4, AHD, AECDH, <2048 DHE bits-->
                <xsl:if test="not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@sslversion = 'TLSv1.1') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH')) and not(./@dhebits &lt; '2048')">
                  <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_DHE-',./@dhebits,'-bits')"/></font><br/>
                </xsl:if>
             </xsl:when>
            </xsl:choose>
            <xsl:choose>
              <!--Find and Check Ciphers with Curve-->
              <xsl:when test="./@ecdhebits">
                <!--Check if SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(contains(./@sslversion,'SSL')) or (./@sslversion = 'TLSv1.0') or (./@bits &lt; '128') or (contains(./@cipher,'RC4')) or (contains(./@cipher,'AHD')) or (contains(./@cipher,'AECDH'))">
                  <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_Curve-',./@curve,'-DHE-',./@ecdhebits)"/></font><br/>
                </xsl:if>
                <!--Check if TLSv1.1 and not SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(./sslversion = 'TLSv1.1') and not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH'))">
                  <font class="risk2"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_Curve-',./@curve,'-DHE-',./@ecdhebits)"/></font><br/>
                </xsl:if>
                <!--Check if not SSL, TLSv1.0, TLSv1.1, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@sslversion = 'TLSv1.1') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH'))">
                  <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher,'_Curve-',./@curve,'-DHE-',./@ecdhebits)"/></font><br/>
                </xsl:if>
              </xsl:when>
            </xsl:choose>
            <xsl:choose>
              <!--Check Ciphers without DHE or Curve-->
              <xsl:when test="not(./@dhebits) and not(./@ecdhebits)">
                <!--Check if SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(contains(./@sslversion,'SSL')) or (./@sslversion = 'TLSv1.0') or (./@bits &lt; '128') or (contains(./@cipher,'RC4')) or (contains(./@cipher,'AHD')) or (contains(./@cipher,'AECDH'))">
                  <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/></font><br/>
                </xsl:if>
                <!--Check if TLSv1.1 and not SSL, TLSv1.0, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="(./sslversion = 'TLSv1.1') and not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH'))">
                  <font class="risk2"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/></font><br/>
                </xsl:if>
                <!--Check if not SSL, TLSv1.0, TLSv1.1, <128 bits, RC4, AHD, AECDH-->
                <xsl:if test="not(contains(./@sslversion,'SSL')) and not(./@sslversion = 'TLSv1.0') and not(./@sslversion = 'TLSv1.1') and not(./@bits &lt; '128') and not(contains(./@cipher,'RC4')) and not(contains(./@cipher,'AHD')) and not(contains(./@cipher,'AECDH'))">
                  <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@cipher)"/></font><br/>
                </xsl:if>
              </xsl:when>
            </xsl:choose>
          </xsl:if>
        </xsl:for-each>
      </td>

      <td><!--Key Exchange Groups Cell-->
        <xsl:choose>
          <xsl:when test="./group">
            <xsl:for-each select="./group">
              <xsl:if test="(./@id = '0x0001') or (./@id = '0x0002') or (./@id = '0x0003') or (./@id = '0x0004') or (./@id = '0x0005') or (./@id = '0x000f') or (./@id = '0x0010') or (./@id = '0x0011') or (./@id = '0x0012') or (./@id = '0x0013')">
                <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@name)"/></font><br/>
              </xsl:if>
             <xsl:if test="not(./@id = '0x0001') and not(./@id = '0x0002') and not(./@id = '0x0003') and not(./@id = '0x0004') and not(./@id = '0x0005') and not(./@id = '0x000f') and not(./@id = '0x0010') and not(./@id = '0x0011') and not(./@id = '0x0012') and not(./@id = '0x0013')">
                <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,'_',./@bits,'-bits_',./@name)"/></font><br/>
              </xsl:if>
            </xsl:for-each>
          </xsl:when>
        </xsl:choose>
      </td>

      <td><!--Server Signature Algorithms Cell-->
        <xsl:choose>
          <xsl:when test="./connection-signature-algorithm">
            <xsl:for-each select="./connection-signature-algorithm">
             <xsl:if test="(./@id = '0xfdff')">
                <font class="risk3">-Server accepts all signature algorithms</font><br/>
             </xsl:if>
             <xsl:if test="(./@id = '0x0001') or (./@id = '0x0002') or (./@id = '0x0003') or (./@id = '0x0101') or (./@id = '0x0102') or (./@id = '0x0103') or (./@id = '0x0201') or (./@id = '0x0202') or (./@id = '0x0203') or (./@id = '0x0302') or (./@id = '0x0402') or (./@id = '0x0502') or (./@id = '0x0602')">
                <font class="risk3"><xsl:value-of select="concat('-',./@sslversion,'_',./@name)"/></font><br/>
              </xsl:if>
              <xsl:if test="(./@id = '0x0301') or (./@id = '0x0303')">
                <font class="risk2"><xsl:value-of select="concat('-',./@sslversion,'_',./@name)"/></font><br/>
              </xsl:if>
              <xsl:if test="not(./@id = '0x0001') and not(./@id = '0x0002') and not(./@id = '0x0003') and not(./@id = '0x0101') and not(./@id = '0x0102') and not(./@id = '0x0103') and not(./@id = '0x0201') and not(./@id = '0x0202') and not(./@id = '0x0203') and not(./@id = '0x0302') and not(./@id = '0x0402') and not(./@id = '0x0502') and not(./@id = '0x0602') and not(./@id = '0x0301') and not(./@id = '0x0303') and not(./@id = '0xfdff')">
                <font class="risk1"><xsl:value-of select="concat('-',./@sslversion,'_',./@name)"/></font><br/>
              </xsl:if>
            </xsl:for-each>
          </xsl:when>
        </xsl:choose>
      </td>

      <td><!--Certificate Checks Cell-->
        <!--Check Subject and Issuer-->
        <xsl:if test="./certificates/certificate/self-signed = 'true'">
          <font class="risk3"><xsl:value-of select="concat('-Subject: ',./certificates/certificate/subject)"/></font><br/>
          <font class="risk3"><xsl:value-of select="concat('-Issuer: ',./certificates/certificate/issuer)"/></font><br/>
        </xsl:if>
        <xsl:if test="./certificates/certificate/self-signed = 'false'">
          <font class="risk1"><xsl:value-of select="concat('-Subject: ',./certificates/certificate/subject)"/></font><br/>
          <font class="risk1"><xsl:value-of select="concat('-Issuer: ',./certificates/certificate/issuer)"/></font><br/>
        </xsl:if>
        <!--Get Dates-->
        <xsl:choose>
          <xsl:when test="./certificates/certificate/not-valid-before">
            <font class="risk1"><xsl:value-of select="concat('-Invalid Before: ',./certificates/certificate/not-valid-before)"/></font><br/>
          </xsl:when>
        </xsl:choose>
        <xsl:if test="./certificates/certificate/expired = 'true'">
          <font class="risk3"><xsl:value-of select="concat('-Invalid After: ',./certificates/certificate/not-valid-after)"/></font><br/>
        </xsl:if>
        <xsl:if test="./certificates/certificate/expired = 'false'">
          <font class="risk1"><xsl:value-of select="concat('-Invalid After: ',./certificates/certificate/not-valid-after)"/></font><br/>
        </xsl:if>
        <!--Check Signature Algorithm-->
        <xsl:choose>
          <xsl:when test="./certificates/certificate/signature-algorithm">
            <xsl:if test="contains(./certificates/certificate/signature-algorithm,'sha1') or contains(./certificates/certificate/signature-algorithm,'md5')">
              <font class="risk3"><xsl:value-of select="concat('-',./certificates/certificate/signature-algorithm)"/></font><br/>
            </xsl:if>
            <xsl:if test="not(contains(./certificates/certificate/signature-algorithm,'sha1')) and not(contains(./certificates/certificate/signature-algorithm,'md5'))">
              <font class="risk1"><xsl:value-of select="concat('-',./certificates/certificate/signature-algorithm)"/></font><br/>
            </xsl:if>
          </xsl:when>
        </xsl:choose>
        <!--Check Key Strength-->
        <xsl:if test="./certificates/certificate/pk/@bits &lt; '2048'">
          <font class="risk3"><xsl:value-of select="concat('-',./certificates/certificate/pk/@type,' Key: ',./certificates/certificate/pk/@bits,' bits')"/></font><br/>
        </xsl:if>
        <xsl:if test="./certificates/certificate/pk/@bits &gt; '2047'">
          <font class="risk1"><xsl:value-of select="concat('-',./certificates/certificate/pk/@type,' Key: ',./certificates/certificate/pk/@bits,' bits')"/></font><br/>
        </xsl:if>
      </td>
    </tr>
    </xsl:for-each>
  </table>
<!--End Full Results Table-->

</body>
</html>
</xsl:template>
</xsl:stylesheet>
