#!/usr/bin/python

import sys
import os.path
import xml.etree.ElementTree
import xlsxwriter

def usage():
	print('Nessus XML report to XLS by UND3R\nUsage: %s input output risk\n\nInformation Arguments\n\ninput: XML Nessus Report (nessus_report.xml)\noutput: XLSX Output (output.xlsx)\nrisk: Minimum risk (none, low, medium, high, critical)' % (sys.argv[0]))
	exit(1)

def parse(input_file, risk, worksheet):
	root = xml.etree.ElementTree.parse(input_file).getroot()
	report_host = root.findall('Report/ReportHost')

	row_count = 2

	for report_host_elements in report_host:
		os = report_host_elements.findall('HostProperties/tag[@name=\'os\']')
		os = os[0].text

		ip_address = report_host_elements.findall('HostProperties/tag[@name=\'host-ip\']')
		ip_address = ip_address[0].text

		dns_name = report_host_elements.findall('HostProperties/tag[@name=\'host-rdns\']')
		dns_name = dns_name[0].text

		netbios_name = report_host_elements.findall('HostProperties/tag[@name=\'netbios-name\']')

		if(len(netbios_name) == 0):
			netbios_name = '-'
		else:
			netbios_name = netbios_name[0].text

		report_item = root.findall('Report/ReportHost/ReportItem')

		for report_item_attrib in report_item:
			port = report_item_attrib.attrib['port']
			severity = report_item_attrib.attrib['severity']
			vulnerability_name = report_item_attrib.attrib['pluginName']
			finding_category = report_item_attrib.attrib['pluginFamily']
			
			cvss_description = '-'
			cvss_description_find = report_item_attrib.find('cvss3_vector')

			if cvss_description_find is not None:
				cvss_description = cvss_description_find.text
				
			finding_description = report_item_attrib.find('description').text

			impact = report_item_attrib.find('risk_factor').text
			
			if impact == 'None':
				current_risk = 1
			elif impact == 'Low':
				current_risk = 2
			elif impact == 'Medium':
				current_risk = 3
			elif impact == 'High':
				current_risk = 4
			else:
				current_risk = 5

			if current_risk < risk:
				continue

			recommendation_text = report_item_attrib.find('solution').text

			if recommendation_text == 'n/a':
				recommendation_text = '-'

			additionals_details = report_item_attrib.find('plugin_output')

			if(additionals_details is None):
				additionals_details = '-'
			else:
				additionals_details = additionals_details.text

			worksheet.write('A' + str(row_count), '-')
			worksheet.write('B' + str(row_count), severity)
			worksheet.write('C' + str(row_count), '-')
			worksheet.write('D' + str(row_count), '-')
			worksheet.write('E' + str(row_count), '-')
			worksheet.write('F' + str(row_count), vulnerability_name)
			worksheet.write('G' + str(row_count), ip_address)
			worksheet.write('H' + str(row_count), dns_name)
			worksheet.write('I' + str(row_count), '-')
			worksheet.write('J' + str(row_count), netbios_name)
			worksheet.write('K' + str(row_count), os)
			worksheet.write('L' + str(row_count), port)
			worksheet.write('M' + str(row_count), finding_category)
			worksheet.write('N' + str(row_count), finding_description)
			worksheet.write('O' + str(row_count), impact)
			worksheet.write('P' + str(row_count), recommendation_text)
			worksheet.write('Q' + str(row_count), additionals_details)
			worksheet.write('R' + str(row_count), cvss_description)
			worksheet.write('S' + str(row_count), '-')
			worksheet.write('T' + str(row_count), '-')
			worksheet.write('U' + str(row_count), '-')
			worksheet.write('V' + str(row_count), '-')
			worksheet.write('W' + str(row_count), '-')
			worksheet.write('X' + str(row_count), '-')
			worksheet.write('Y' + str(row_count), '-')
			worksheet.write('Z' + str(row_count), '-')
			worksheet.write('AA' + str(row_count), '-')
			worksheet.write('AB' + str(row_count), '-')
			worksheet.write('AC' + str(row_count), '-')
			worksheet.write('AD' + str(row_count), '-')
			worksheet.write('AE' + str(row_count), '-')
			worksheet.write('AF' + str(row_count), '-')

			row_count += 1
	return

def generate_header(worksheet):
	worksheet.write('A1', 'worksheet')
	worksheet.write('B1', 'Severity')
	worksheet.write('C1', 'Due Date')
	worksheet.write('D1', 'Days Overdue')
	worksheet.write('E1', 'Recidivism Count')
	worksheet.write('F1', 'Vulnerability Name')
	worksheet.write('G1', 'IP Address')
	worksheet.write('H1', 'DNS Name')
	worksheet.write('I1', 'Request URL')
	worksheet.write('J1', 'Net Bios Name')
	worksheet.write('K1', 'OS')
	worksheet.write('L1', 'Port')
	worksheet.write('M1', 'Finding Category')
	worksheet.write('N1', 'Finding Description')
	worksheet.write('O1', 'Impact')
	worksheet.write('P1', 'Recommendation Text')
	worksheet.write('Q1', 'Additional Details')
	worksheet.write('R1', 'CVSS Description')
	worksheet.write('S1', 'First Found Date')
	worksheet.write('T1', 'Last Found Date')
	worksheet.write('U1', 'Validation Date')
	worksheet.write('V1', 'Last Host Scan Date')
	worksheet.write('W1', 'Age')
	worksheet.write('X1', 'Days Since Last Clean')
	worksheet.write('Y1', 'Last Validation Date')
	worksheet.write('Z1', 'Assignee Name')
	worksheet.write('AA1', 'Assignee Area Description')
	worksheet.write('AB1', 'ORGANIZATION')
	worksheet.write('AC1', 'ENVIRONMENT')
	worksheet.write('AD1', 'PLATFORM')
	worksheet.write('AE1', 'Network Location')
	worksheet.write('AF1', 'Status')
	return

def main():
	if(len(sys.argv) < 4):
		usage()
	
	input_file = sys.argv[1]
	output_file = sys.argv[2]
	risk = sys.argv[3]

	if risk == 'none':
		risk = 1
	elif risk == 'low':
		risk = 2
	elif risk == 'medium':
		risk = 3
	elif risk == 'high':
		risk = 4
	elif risk == 'critical':
		risk = 5
	else:
		usage()

	if not os.path.exists(input_file):
		print('The file "%s" not exist!' % (input_file))
		exit(1)

	workbook = xlsxwriter.Workbook(output_file)
	worksheet = workbook.add_worksheet()

	generate_header(worksheet)

	parse(input_file, risk, worksheet)

	workbook.close()

if __name__== "__main__":
  main()
