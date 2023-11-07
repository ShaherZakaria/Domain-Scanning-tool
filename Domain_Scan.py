from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import requests
import json
import csv
from MToken import Mandiant_Token

# Define your API keys
IBM_Key = 'IBM_Key'
AV_Key = 'AV_Key'
MANDIANT_API_KEY = Mandiant_Token
Virus_Total_Key='Virus_Total_Key'
# File paths
input_file = r"\Path\Domains.txt"
output_file_csv = r"\Path\RES.csv"
output_file_text = r"\Path\RES.txt"

# Initialize threat intelligence services
otx = OTXv2(AV_Key)
MANDIANT_API_headers = {
    "Authorization": f"Bearer {MANDIANT_API_KEY}",
    "Accept": "application/json",
}

IBM_headers = {
    'Authorization': f'{IBM_Key}'
}

Virus_Total_headers = {
    "accept": "application json",
    "x-apikey": "Virus_Total_Key"
}

# Create and open output files
with open(output_file_text, 'w', newline='') as text_file:
    pass

with open(output_file_csv, 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["Domain", "VT_Tags", "MSCORE", "VT_Malicious", "XForce", "Alien_Vault Pulses"])

    with open(input_file, "r") as domains:
        for x in domains:
            x = x.strip()  # Remove trailing newline character

            url = f"https://www.virustotal.com/api/v3/domains/{x}"
            IBM_URL = f'https://api.xforce.ibmcloud.com/url/domain/{x}'
            MANDIANT_API_URL = f"https://api.intelligence.mandiant.com/v4/indicator/fqdn/{x}"

            # Make API requests
            Virus_Total_response = requests.get(url, headers=Virus_Total_headers)
            IBM_response = requests.get(IBM_URL, headers=IBM_headers)
            MANDIANT_API_response = requests.get(MANDIANT_API_URL, headers=MANDIANT_API_headers)

            response = response.text
            IBM_response = IBM_response.text
            MANDIANT_API_response = MANDIANT_API_response.text

            Virus_Total_result = json.loads(Virus_Total_response)
            IBM_result = json.loads(IBM_response)
            AV_result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, f"{x}", section="general")
            MANDIANT_API_response = json.loads(MANDIANT_API_response)

            res1 = Virus_Total_result['data']['attributes']['last_analysis_stats']['malicious']
            res2 = Virus_Total_result['data']['attributes']['tags']
            AV_res = AV_result['pulse_info']['count']

            try:
                Mandiant_Score = MANDIANT_API_response['mscore']
            except KeyError:
                Mandiant_Score = 0

            # Write data to the CSV file
            csv_writer.writerow([x, json.dumps(res2), json.dumps(Mandiant_Score), json.dumps(res1), '', AV_res])

            # Write data to the text file
            with open(output_file_text, 'a') as text_output:
                text_output.write(x + '\n\n')
                text_output.write(f"Mandiant Score: {json.dumps(Mandiant_Score)}\n\n")
                text_output.write("Virus_Total\n")
                text_output.write(json.dumps(Virus_Total_result['data']['attributes']['last_analysis_stats']) + '\n')
                text_output.write(f"Tags{json.dumps(res2)}\n\n")
                text_output.write("Alien_Vault\n")
                text_output.write(json.dumps(AV_result['pulse_info']) + '\n\n' + '----------------------------------------------------------------\n')

            print("Domain:", x)
            print("Virus_Total Stats:", res1)
            print("Virus_Total Tags:", res2)
            print("Alien_Vault Info:", AV_res)
            print(f"Mandiant Score: {Mandiant_Score}\n")
