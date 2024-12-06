import re
import pandas as pd
import argparse

#---------------------------- Count Request PerID---------------------------------

def count_requests_per_ip(log_file):

    
    ip_counts = {}
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' 

    with open(log_file, 'r') as f:
        for line in f:
            ip_address = re.search(ip_pattern, line)
       
           
            if ip_address:
                ip_address = ip_address.group()
           

                if ip_address in ip_counts:
                    ip_counts[ip_address] += 1
                else:
                    ip_counts[ip_address] = 1    

    # Sort by request count in descending order
    
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_ip_counts

if __name__ == '__main__':
    log_file = "C:\\Users\\DELL\\Desktop\\python_assignment_vrv_security\\sample.log" 
    

    ip_counts = count_requests_per_ip(log_file)
   

    print('Requests per IP:')
    print('-------------------------------')   
    print("IP Address\t| Request Count")
    print('----------------|--------------')
    for ip, count in ip_counts:
       
        print(f"{ip}\t|\t{count}")
    print('------------------------------')    




# -------------Most Frequently Accessed Endpoint-----------------------------------------

def most_frequently_accessed_points(log_file):

    endpoint_counts = {}
    endpoint_pattern = r"\/(home|login|about|contact|dashboard|profile|register|feedback)"


    with open(log_file, 'r') as f:

        for line in f:
            endpoints = re.search(endpoint_pattern,line)

            if endpoints:
                endpoints = endpoints.group()

                if endpoints in endpoint_counts:
                    endpoint_counts[endpoints] += 1

                else:
                    endpoint_counts[endpoints] = 1


    most_frequent = max(endpoint_counts,key = endpoint_counts.get)
    count = endpoint_counts[most_frequent]
    

    return [(most_frequent,count)]


if __name__ == '__main__':
    log_file = "C:\\Users\\DELL\\Desktop\\python_assignment_vrv_security\\sample.log" 
    
    most_occured_points = most_frequently_accessed_points(log_file)
    for most_frequent,count in most_occured_points:
        print(f'Most Frequently Accessed Endpoint:\n{most_frequent} (Accessed {count} times)')

    if len(most_occured_points) == 0:
        print('No endpints are available.')    

    print('------------------------------')




#---------Suspicious Activity Detected-----------------------------------------------------


def detect_brute_force(log_file, threshold):


    failed_attempts = {}
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    statuscode_pattern = r'(401)' 
    
    specific_message = "Invalid credentials"


    with open(log_file, 'r') as f:
        for line in f:
           
            ip_address = re.search(ip_pattern, line)
            status_code = re.search(statuscode_pattern, line) 

        
            if (ip_address and (status_code or specific_message in line)):
                ip_address = ip_address.group()

                if status_code:
                    status_code = status_code.group()
                 
                
                if ip_address in failed_attempts:
                    failed_attempts[ip_address] += 1

                else:
                    failed_attempts[ip_address] = 1
                    
    failed_ips = []
   
    for ip in failed_attempts:
        if failed_attempts[ip] >= threshold:
            failed_ips.append((ip,failed_attempts[ip]))

    return failed_ips

                

log_file = "C:\\Users\\DELL\\Desktop\\python_assignment_vrv_security\\sample.log"
default_threshold = 10
parser = argparse.ArgumentParser()
parser.add_argument("--threshold", type=int, help="Override the default threshold")
args = parser.parse_args()

threshold = args.threshold or default_threshold
suspicious_ips = detect_brute_force(log_file,threshold)



if suspicious_ips:
    print("Suspicious Activity Detected:")
    print('-----------------------------------------')
    print("IP Address\t| Failed Login Attempts")
    print('----------------|------------------------')
    for ip, count in suspicious_ips:
        print(f"{ip}\t|\t{count}")
else:
    print("No suspicious activity detected.")    
    



#---------------------display result in csv-----------------------

ip_list = []
count_list = []

for ip,count in ip_counts:
    ip_list.append(ip)
    count_list.append(count)


endpoint_list = []
accesscount_list = []

for endpoint,accesscount in most_occured_points:
    endpoint_list.append(endpoint)
    accesscount_list.append(accesscount)



ip_fail_list = []
failed_count_list = []

for ip,failed_list in suspicious_ips:
    ip_fail_list.append(ip)
    failed_count_list.append(failed_list)






requests_per_ip = pd.DataFrame({'IP Address': ip_list,
                                 'Request Count': count_list})

most_accessed_endpoint = pd.DataFrame({'Endpoint': endpoint_list,
                                      'Access Count': accesscount_list})

suspicious_activity = pd.DataFrame({'IP Address': ip_fail_list,
                                   'Failed Login Count': failed_count_list})


columns = pd.MultiIndex.from_tuples([('Requests per IP', 'IP Address'),
                                     ('', 'Request Count'),
                                     ('Most Accessed Endpoint', 'Endpoint'),
                                     ('', 'Access Count'),
                                     ('Suspicious Activity', 'IP Address'),
                                     ('', 'Failed Login Count')])

df = pd.concat([requests_per_ip, most_accessed_endpoint, suspicious_activity], axis=1)
df.columns = columns


df.to_csv('log_analysis_results.csv',index=False)
