# CVE Mining Project

### Project Files
    CVE_spider.py
    CVE_record_generator.py
### Project Dependencies
  * Scrapy 2.4.1
  * Python 3.8.8
  * Pandas 1.2.3
### Description
Two semi-automated python program to automated the process of obtaining CVE information from MITRE's CVE database (https://cve.mitre.org) and then creating records based on the crawled data.
### Usage
<b>CVE_spider.py</b>
The spider needs to be dropped in an initialized Scrapy's "spiders" folder, follow the directions linked below to create a local Scrapy project.
<a href="https://docs.scrapy.org/en/latest/intro/tutorial.html#creating-a-project">Scrapy Documentation</a>

The spider then can be run from the project's top level directory with the following command

    scrapy crawl CVE_gold_miner

The above command will then generate a output file containing the crawled data in a csv file format.

Input:

&nbsp;&nbsp;&nbsp;&nbsp;Column of CVE_IDs to crawl in csv format named (CVE-ID)

Output:

&nbsp;&nbsp;&nbsp;&nbsp;CVE_Miner_output_batch\<mm-dd-yyyy\>.csv

Output Columns:

&nbsp;&nbsp;&nbsp;&nbsp;CVE_ID: ID of CVE\
&nbsp;&nbsp;&nbsp;&nbsp;CVE_Link: Link to CVE record in MITRE\
&nbsp;&nbsp;&nbsp;&nbsp;Description: MITRE description of CVE\
&nbsp;&nbsp;&nbsp;&nbsp;Reference_Link: Bug fix, commit, and reference links for CVE (Multiple cols)

<b>CVE_record_generator.py</b>\
Input: 

&nbsp;&nbsp;&nbsp;&nbsp;Batch file generated with CVE_spider.py with list of CVEs with detailed and structured data

Input:

&nbsp;&nbsp;&nbsp;&nbsp;CVE_ID: ID of CVE\
&nbsp;&nbsp;&nbsp;&nbsp;CVE_Link: Link to CVE record in MITRE\
&nbsp;&nbsp;&nbsp;&nbsp;Description: MITRE description of CVE\
&nbsp;&nbsp;&nbsp;&nbsp;Reference_Link: Bug fix, commit, and reference links for CVE\ (Multiple cols)

Output:

&nbsp;&nbsp;&nbsp;&nbsp;Create directories, explanation.txt, and fix.diff for each CVE record