import dns.resolver
import dns.exception
from dns.flags import to_text
import time
import sys
import datetime
from sqlite3.dbapi2 import Time

# storing the root servers in an array to use them to resolve for TLDs
rootservers = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230.10","192.5.5.241","192.112.36.4",
               "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]


#this method is used to resolve for the top level domain for any given domain
def resolve_tld(domain,rec_type):
    domains = domain.split('.')
    length = len(domains)
    for i in range(len(rootservers)):
        domain = domains[length-1]
        #the record type changes according to the user input
        if(rec_type == 'A'):
            request = dns.message.make_query(domain, dns.rdatatype.A)
        elif(rec_type == 'NS'):
            request = dns.message.make_query(domain, dns.rdatatype.NS)
        elif(rec_type == 'MX'):
            request = dns.message.make_query(domain, dns.rdatatype.MX)
        #we try to resolve the TLD from root servers stored in the array
        nameserver = rootservers[i]
        try :
            response = dns.query.udp(request, nameserver,5)
            if(response): return response
            
        except:
            print("---------Server not found-----")


#this method is used to resolve the authoritative name server
#once the tld is resolved, this method is called iteratively to find the final authoritative name server
def resolve_ans(domains,response,rec_type):
    domain = domains[len(domains)-1]
    count = len(domains)-1
    for i in range(len(domains)-1 ):
        domain = domains[count-1]+"."+domain
        count-= 1
        domainss =[]
        for j in range (0, len(response.additional)):
            if( (((response.additional[j].to_text()).split(" "))[3])  == 'A'):
                domainss.append((response.additional[j].to_text()).split(" ")[-1])
                
        for k in range(len(domainss)):
            if(rec_type == 'A'):
                request = dns.message.make_query(domain, dns.rdatatype.A)
            elif(rec_type == 'NS'):
                request = dns.message.make_query(domain, dns.rdatatype.NS)
            elif(rec_type == 'MX'):
                request = dns.message.make_query(domain, dns.rdatatype.MX)
        
            nameserver = domainss[k]
            try :
                response = dns.query.udp(request, nameserver,5)
                if(response): break
                    
            except:
                print("---------Server not found-----")
    return response


#this method is used to print the output in the required format
def print_answer(question_sec,time_taken,payload_size,final_response,cname_ans):

    print("QUESTION SECTION\n",question_sec )
    if(final_response.answer ):
        print("ANSWER SECTION:\n", final_response.answer[0])
    if(cname_ans):
        print("ANSWER SECTION : \n", cname_ans[0])
    if(final_response.authority):
        print("AUTHORITY SECTION :\n",final_response.authority[0])
    print("Query Time :", time_taken)
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    print("WHEN :",st)
    print("MSG SIZE rcvd:", payload_size)
    


#def main(str,type):
if __name__ == "__main__":     
    inp1 = sys.argv[1]
    #inp1= str 
    rec_type = sys.argv[2]
    #rec_type = type
    #print("rec type is :", rec_type)
    domains = inp1.split('.')
    length = len(domains)
    start_time = time.time()
    tld_response = resolve_tld(inp1, rec_type)
    final_resp = resolve_ans (domains,tld_response, rec_type)
    while(not (final_resp.answer)):
        final_resp = resolve_ans (domains,final_resp, rec_type)
    is_cname = 0
    question_sec = final_resp.question[0]
    #if the response contains cname after resolving for authoritative name server, then the cname is also resolved iteratively
    if(final_resp.answer and final_resp.answer[0].to_text().split(" ")[3] == 'CNAME'):
        is_cname =1
        cname = final_resp.answer[0].to_text().split(" ")[4]
        if(cname[len(cname)-1] =='.'):
            cname  = cname[:-1]
        domains = (cname).split(".")
        resp = resolve_tld(cname,rec_type)
        resp_cname = resolve_ans(domains, resp,rec_type)
    end_time = time.time()
    time_taken = (end_time-start_time)*1000
    cname_ans = ""
    
    #to calculate the payload size 
    payload_size = 16 + len(inp1)
    if(is_cname == 0):
        final_response = final_resp
    else:
        cname_ans = final_resp.answer
        final_response = resp_cname
    if len(final_response.answer):
        for ans in final_response.answer:
            for rr in ans:
                payload_size += len(rr.to_text())

    if len(final_response.authority):
        for auth in final_response.authority:
            for rr in auth:
                payload_size += len(rr.to_text())

    if len(final_response.additional):
        for add in final_response.additional:
            for rr in add:
                payload_size += len(rr.to_text())

    print_answer(question_sec,time_taken,payload_size,final_response,cname_ans)
    #return time_taken
    
                
    