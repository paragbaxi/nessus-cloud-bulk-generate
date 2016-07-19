# nessus-cloud-bulk-generate
Be able to generate .nessus files that contains thousands of hosts with a variety of vulnerabilities and configurations.

# Why
Be able to migrate large existing .nessus files to Nessus Cloud.

# How it reads real data
1. Use real XML .nessus vuln data.
2. Save each host as a template.
3. Iterate <ReportHost>.

```xml
  <ReportHost name="206.132.3.30">
  	<HostProperties>
  		<tag name="HOST-END">2016-04-21T23:36:51.000Z</tag>
  		<tag name="HOST-START">2016-04-21T23:36:42.000Z</tag>
  		<tag name="id">8830d2b7-3c70-4d90-b756-4107973de27f</tag>
  		<tag name="hostname">206.132.3.30</tag>
  		<tag name="mac-address">38:2c:4a:a4:18:08</tag>
  		<tag name="fqdn">images.bigfootinteractive.com</tag>
  		<tag name="ip">206.132.3.30</tag>
  </HostProperties>
  </ReportHost>
```

Save <ReportItem>.

```xml
<ReportHost name="192.168.254.169">...</ReportHost>
<ReportItem … >...</ReportItem>
<ReportItem … >...</ReportItem>
…
<ReportItem … >...</ReportItem>
<ReportHost name="206.132.3.30">...</ReportHost>
<ReportItem … >...</ReportItem>
…
```

# How it generates

1. Loop until all are read.
2. Write hosts and replace following bold values with dynamically generated host data.
3. Write .nessus file.
4. Import file to Nessus Cloud account
