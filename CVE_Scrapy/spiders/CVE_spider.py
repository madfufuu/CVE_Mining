import scrapy
import csv
import os
import pandas as pd
import datetime


"""
Spider Name: CVE_gold_miner
Usage: To automate process to obtaining CVE data from cve.mitre.org.

input:
	List of CVE_IDs to crawl in csv format
output:
	CVE_Miner_output.csv
	columns: 
		CVE_ID: ID of CVE
		CVE_Link: Link to CVE record in MITRE
		Description: MITRE description of CVE
		Reference_Link: Bug fix, commit, and reference links for CVE (Multiple cols)
"""
class CVE_spider(scrapy.Spider):
    name = "CVE_gold_miner"

    def start_requests(self):
        path = "/Users/yun/Desktop/OneDrive - The University of Texas at Dallas/work/mscs/Spring21/CVE Mining/CVE_Dataset.csv" # Replace with absolute path
        CVE_Mining_Dataset = pd.read_csv(path)
        CVE_IDs = CVE_Mining_Dataset["CVE-ID"].tolist()
        baseUrl = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
        urls = CVE_IDs

        for url in urls:
            yield scrapy.Request(
                url=baseUrl + url,
                callback=self.parse,
                errback=self.retry,
                cb_kwargs=dict(url=url, baseUrl=baseUrl),
            )
            # break

    def parse(self, response, url, baseUrl):
        CVE_ID = response.css("h2::text").extract()
        CVE_Link = [baseUrl + url]
        description = [response.css("tr:nth-child(4) td::text").extract()[0].strip()]
        reference_links = response.css("li a::attr(href)").getall()
        reference_links = [element.strip() for element in reference_links]

        CVE_record = CVE_ID + CVE_Link + description + reference_links

        # Output to csv
        oFilePath = "/Users/yun/Desktop/OneDrive - The University of Texas at Dallas/work/mscs/Spring21/CVE Mining/" # Replace with absolute path
        today = datetime.date.today()
        oFileName = "CVE_Miner_output_batch" + str(today.month) + "-" + str(today.day) + "-" + str(today.year) + ".csv"
        with open(oFilePath + oFileName, "a", newline="") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL, escapechar="\\")
            if os.stat(oFilePath+oFileName).st_size == 0:
                writer.writerow(["CVE_ID", "CVE_Link", "Description"]+["Reference_Link"]*20)
            writer.writerow(CVE_record)

    # Request error handeling
    def retry(self, failure):
        self.logger.exception(repr(failure))

        if failure.check(HttpError):
            # these exceptions come from HttpError spider middleware
            # you can get the non-200 response
            response = failure.value.response
            self.logger.error("HttpError on %s", response.url)
        elif failure.check(DNSLookupError):
            # this is the original request
            request = failure.request
            self.logger.error("DNSLookupError on %s", request.url)
        elif failure.check(TimeoutError, TCPTimedOutError):
            request = failure.request
            self.logger.error("TimeoutError on %s", request.url)

        self.logger.debug(
            "\n\nData for CVE: "
            + failure.request.cb_kwargs["url"]
            + " does not exist..."
        )
