import pandas as pd
import json
assets = pd.read_csv("data-ingestion/data/assets.csv")
network_logs = pd.read_csv("data-ingestion/data/network_logs.csv")
server_logs = pd.read_csv("data-ingestion/data/server_logs.csv")

f = open("data-ingestion/data/vulnerabilities.json","r", encoding="utf-8")
vulnerabilities = json.load(f)


from vulnerability_detection import vulnerable_assets

#detecting suspicious HTTP requests

#print(server_logs['path'].to_list())

suspicious_paths = ['/.env', '/config.php', '/admin']

suspicious_http_requests = server_logs[server_logs['path'].isin(suspicious_paths)]

sus_grouped = suspicious_http_requests.groupby(['source_ip', 'path']).size() 
#print(sus_grouped)

#flag an IP for brute force 

server_logs['timestamp'] = pd.to_datetime(server_logs['timestamp'])
brute_force_ips = set()
for i in range(len(server_logs)):
    start_time = server_logs['timestamp'].iloc[i]
    end_time = start_time + pd.Timedelta(seconds=60)
    brute_force_window = server_logs[(server_logs['timestamp'] >= start_time) & (server_logs['timestamp'] <= end_time)]

    brute_force = brute_force_window[(brute_force_window['status'] == 401)&
                                     (brute_force_window['method'] == 'POST')&
                                     (brute_force_window['path'] == '/login')].groupby(['source_ip']).size()
    brute_force_ips.update(brute_force.index)
    

brute_force_logs = server_logs[server_logs['source_ip'].isin(brute_force_ips)]

suspicious_HTTP_asset_ids = suspicious_http_requests['asset_id'].unique() 
brute_force_unique_assets = brute_force_logs['asset_id'].unique() 

all_flagged_assets = set(vulnerable_assets).union(set(suspicious_HTTP_asset_ids)).union(set(brute_force_unique_assets))
"""
for index, asset in assets.iterrows():
    if asset['asset_id'] in all_flagged_assets:
        print(f"Asset {asset['asset_id']} is flagged for further investigation.")"""

security_report = []
engine_output = []

for asset in all_flagged_assets:
    asset_output = {
        "asset_id": asset,
        "Vulnerability": asset in vulnerable_assets,
        "Suspicious_HTTP": asset in suspicious_HTTP_asset_ids,
        "Brute_Force": asset in brute_force_unique_assets
    }
    engine_output.append(asset_output)

with open("engine/intermediate_output/correllated_events.json", "w", encoding="utf-8") as outfile:
    json.dump(engine_output, outfile, indent=4)

#json.dump(engine_output, f1, indent=4)