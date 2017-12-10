#python2.7.x compiled on Python 2.7.10 :: Anaconda 2.3.0 (64-bit)
#CveDetailsScaper.py
#A small python script used for scraping the CVE Details website for collating the following information
# CVE-ID,Severity,Product,Vendor,Summary (Primary required fields, many additional fields shall be present)

from bs4 import BeautifulSoup
import requests,pprint,sys,datetime,re
from argparse import ArgumentParser
import requests,pprint,csv,os,datetime,re,urllib
import pandas as pd
from pandas import ExcelWriter
from pandas import ExcelFile
import calendar
import smtplib,ssl
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import formatdate
from email import encoders
import datetime
import re

#import requests.packages.urllib3.util.ssl_
#print(requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS)
#requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

cveIDNumber=[]
summaryText=[]
publishDate=[]
softwareType=[]
vendor=[]
product=[]
version=[]
cvssScore=[]
confidentialityImpact=[]
integrityImpact=[]
availibilityImpact=[]
accessComplexity=[]
authentication=[]
gainedAccess=[]
vulnType=[]
exploitAvailible=[]
temp=[]

confidentialityImpactTup=('Complete','None','Partial')
integrityImpactTup=('Complete','None','Partial')
availibilityImpactTup=('Complete','None','Partial')
accessComplexityTup=('Low','Medium','High') #Low means , accessible easily.
authenticationRequiredTup=('Not Required','Single System') #Single System implies that attacker requires a session.
accessLevelGainedTup=('None','Admin') #What is the access Level gained by exploiting this vulnerability



def parse_arguments(): # Function for parsing command line arguments
	parser = ArgumentParser(description='A small python script used for scraping the CVE Details website for collating the following information'+'\n'+'# CVE-ID,Severity,Product,Vendor,Summary (Primary required fields, many additional fields shall be present)')
	parser.add_argument('-smin',help='Minimum Severity Rating',default=7)
	parser.add_argument('-smax',help='Minimum Severity Rating',default=10)
	parser.add_argument('-m',help='Month in Number viz 1-12',default=datetime.date.today().month)
	parser.add_argument('-y',help='Year in YYYY',default=datetime.date.today().year)
	args=parser.parse_args()
	return args

def createFullUrl(smin,smax,year,month,page):
	url = "http://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page="+str(page)+"&cvssscoremin="+str(smin)+"&cvssscoremax="+str(smax)+"&year="+str(year)+"&month="+str(month)+"&order=3"
	print (url)
	
	
	
	return url

def getSoupHTML(url):
	response=requests.get(url)
	html=response.content
	soup = BeautifulSoup(html,"html.parser")
	##pprint.pprint(soup)
	return soup

def getCVEIds(soup,cveArray):
	table = soup.find('table',attrs={'class','searchresults'})
	for a in table.find_all('a',href=True):
		m = re.search("CVE-\d{4}-\d{4,7}",a['href'])
		if m:
			cveArray.append(m.group(0))
		
def getCVEPages(soup):
	cveIDPages=[]
	items=soup.find_all('div',class_="paging")
	for item in items:
		links=item.find_all('a')
		for link in links:
			cveIDPages.append("http://www.cvedetails.com/"+str(link['href']))
	
	return cveIDPages

def getCVEDetails(cveID):
	url="http://www.cvedetails.com/cve/"+cveID
	soup=getSoupHTML(url)
	
def getCVEDetails(cveid=''):
	cveUrl='http://www.cvedetails.com/cve/'+cveid+'/'
	response = requests.get(cveUrl)
	cveHtml=response.content
	soup = BeautifulSoup(cveHtml,"html.parser")
	if soup =='':
		return
	cveIDNumber.append(cveid)
	table = soup.find(id='vulnprodstable')
	cvssTable = soup.find(id='cvssscorestable')
	summarySoup=soup.find('div',class_="cvedetailssummary")
	summaryText.append(summarySoup.text.split("\n")[1])
	dateStr=summarySoup.text.split("\n")[3]
	publishDate.append(dateStr.split("\t")[1 ].split(":")[1])
	productData=[]

	if 'Please check again' in table.text:
		productData.append('')
		softwareType.append('')
		vendor.append('')
		product.append('')
		version.append('')
	else:
		for row in table.findAll('tr')[::-1]: #Get only the last row
			cols=row.findAll('td')
			for i in range(len(cols)):
				productData.append(cols[i].text.strip())
		softwareType.append(productData[1])
		vendor.append(productData[2])
		product.append(productData[3])
		version.append(productData[4])
		
	cvssData=[]
	for row in cvssTable.findAll('tr'): #Get only the first row
		cols=row.findAll('td')
		for i in range(len(cols)):
			cvssData.append(cols[i].text.strip())
	#pprint.pprint(cvssData)
	cvssScore.append(cvssData[0])
	ci=cvssData[1].split("\n")[0]
	confidentialityImpact.append(ci)
	ii=cvssData[2].split("\n")[0]
	integrityImpact.append(ii)
	ai=cvssData[3].split("\n")[0]
	availibilityImpact.append(ai)
	ac=cvssData[4].split("\n")[0]
	accessComplexity.append(ac)
	ar=cvssData[5].split("\n")[0]
	authentication.append(ar)
	al=cvssData[6].split("\n")[0]
	gainedAccess.append(al)
	vulnType.append(cvssData[7])


def checkCVE(cveIDList,TextList):
		dataFile = open("keyword.txt")
		lines = dataFile.readlines()
		keyword = []
		for x in lines:
			keyword.append(x.split(' ')[0])
		dataFile.close()
		# print (keyword)
		
		# matchID = []
		
		# if any("abc" in s for s in some_list):
		
		# for word in keyword:
		# 	index = 0
		# 	for matchStr in TextList
		# 		if (matchStr.findall(word)): matchedID.append(cveIDList[index])
		# print (matchID + '\n')

	
def writeToExcel(fileName=''):
	print ("Writing to Excel File : "+fileName)
	data = {'CVE ID Number': cveIDNumber, 'Summary Text': summaryText, 'Publish Date': publishDate, 'Software Type': softwareType, 'Vendor': vendor,'Product':product,'Version':version,'CVSS Score':cvssScore,'Confidentiality Impact':confidentialityImpact,'Integrity Impact':integrityImpact,'Availibility Impact':availibilityImpact,'Access Complexity':accessComplexity,'Authentication':authentication,'Gained Access':gainedAccess,'Vulnerability Type':vulnType}
	df = pd.DataFrame(data,columns=['CVE ID Number','Publish Date', 'Software Type','Vendor','Product','Version','CVSS Score','Confidentiality Impact','Integrity Impact','Availibility Impact','Access Complexity','Authentication','Gained Access','Vulnerability Type','Summary Text'])
	writer = ExcelWriter(fileName)


	dataFile = open("keyword.txt")
	lines = dataFile.readlines()
	keyword = []
	for x in lines:
		keyword.append(x.split(' ')[0])
	dataFile.close()
	#checkCVE(cveIDNumber, summaryText)
	# check if there are matched CVE data with the keyword
	mailcontent = ''
	for word in keyword:
				for count in range(len(cveIDNumber)):
					if ' ' + word + ' ' in summaryText[count]:					
						mailcontent = "Found keyword match " + word + '\n'
						mailcontent = cveIDNumber[count] + '\n'
						mailcontent = summaryText[count] + '\n'
	print (mailcontent)

	df.to_excel(writer,'CVE Details',index=False)
	writer.save()
	print ("Completed.")
	return mailcontent

def sendemail(fileName, mailtext):

	textfile = 'Sending CVE data'
	message = MIMEMultipart()
	message['From'] = 'CVE Detail'
	message['To'] =  'Security Team'
	subject = 'CVE Detail announcement on ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	message['Subject'] = subject
	message.attach(MIMEText('Latest CVE Detail Announcement List as attached'))
	message.attach(MIMEText(mailtext))

	part = MIMEBase('application','vnd.ms-excel')
	part.set_payload(open(fileName, "rb").read())
	encoders.encode_base64(part)
	part.add_header('Content-Disposition', 'attachment; filename=CVE Report.xls')
	message.attach(part)

	smtp_server = 'smtp.gmail.com'
	from_mail = 'tomchu12345@gmail.com'
	to_mail = 'chu_liang_han@hotmail.com'

	s = smtplib.SMTP('smtp.gmail.com', 587)
	strGmailUser = 'tomchu12345@gmail.com'
	strGmailPassword = 'b120888280'
	s.ehlo()
	s.starttls()
	s.login(strGmailUser, strGmailPassword)
	s.sendmail(from_mail, to_mail, message.as_string())
	s.quit()
	

	
def main():
	args = parse_arguments()
	if args.m:
		month=int(args.m)
	if args.y:
		year=int(args.y)
	if args.smin:
		smin=int(args.smin)
	if args.smax:
		smax=int(args.smax)
	print (args)
	
	fileName="Security_Advisory_"+calendar.month_name[month]+"_"+str(year)+".xlsx"
	fullUrl=createFullUrl(smin,smax,year,month,1)
	#print fullUrl
	soupObject=getSoupHTML(fullUrl)
	cvePagesArray=getCVEPages(soupObject)
	cveArray=[]
	for cvePage in cvePagesArray:
		#print cvePage
		soupObject=getSoupHTML(cvePage)
		getCVEIds(soupObject,cveArray)
	
	count=0
	for cve in cveArray:
		getCVEDetails(cve)
		count=count+1
		print ("Getting Details for CVE ID: "+cve+". Completed "+str(count)+" Out of "+str(len(cveArray)))
	
	mail = writeToExcel(fileName)
	#sendemail(fileName, mail)

if __name__ == '__main__':
	status = main()
	sys.exit(status)
