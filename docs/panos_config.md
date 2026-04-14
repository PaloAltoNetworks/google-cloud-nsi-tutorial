# NGFW Manual Configuration

This document explains how to manually configure the firewall for NSI if you are not using bootstrapping.

## Apply Baseline Configuration
Configure the firewall to pass the load balancer's health checks and to allow traffic from the `consumer-vpc`.

1. Log into the NGFW's command line interface.

2. Enter configuration mode. 

    ```
    configure
    ```

2. Set a password for the `admin` user.

    ```
    set mgt-config users admin password
    ```

3. Set `ethernet1/1` as a DHCP interface, assign it to the `data` zone, and set its virtual router to `default`.

    ```
    set network interface ethernet ethernet1/1 layer3 dhcp-client enable yes
    set network virtual-router default interface ethernet1/1
    set zone data network layer3 ethernet1/1
    ```

4. Create a management profile (`gcp-lb-profile`) allowing HTTPS from the load balancer's [health check ranges](https://cloud.google.com/load-balancing/docs/health-check-concepts#ip-ranges).

    ```
    set network profiles interface-management-profile gcp-lb-profile https yes
    set network profiles interface-management-profile gcp-lb-profile permitted-ip 35.191.0.0/16
    set network profiles interface-management-profile gcp-lb-profile permitted-ip 130.211.0.0/22
    set network profiles interface-management-profile gcp-lb-profile permitted-ip 209.85.152.0/22
    set network profiles interface-management-profile gcp-lb-profile permitted-ip 209.85.204.0/22
    ```

5. Create a static address group (`gcp-lb-check-ips`) containing the load balancer health check ranges. 

    ```
    ​​set address gcp-lb-check-ip-1 ip-netmask 35.191.0.0/16
    set address gcp-lb-check-ip-2 ip-netmask 120.211.0.0/22
    set address gcp-lb-check-ip-3 ip-netmask 209.85.152.0/22
    set address gcp-lb-check-ip-4 ip-netmask 209.85.204.0/22
    set address-group gcp-lb-check-ips static [ gcp-lb-check-ip-1 gcp-lb-check-ip-2 gcp-lb-check-ip-3 gcp-lb-check-ip-4 ]
    ```

6. Create an address group (`gcp-lb-fwd-rules`) to contain the IP addresses for each forwarding rule. 

    ```
    set address-group gcp-lb-fwd-rules
    ```

7. Create a security policy (`gcp-lb-check-allow`) allowing the health check CIDRs to reach the loopback interfaces using SSL. 

    ```
    set rulebase security rules gcp-lb-check-allow from any to any 
    set rulebase security rules gcp-lb-check-allow source gcp-lb-check-ips
    set rulebase security rules gcp-lb-check-allow destination gcp-lb-fwd-rules
    set rulebase security rules gcp-lb-check-allow application ssl 
    set rulebase security rules gcp-lb-check-allow service application-default
    set rulebase security rules gcp-lb-check-allow action allow
    ```

8. Create a security policy to allow workload traffic from the `consumer-vpc`.

    ```
    set rulebase security rules data-allow from data to data 
    set rulebase security rules data-allow source any
    set rulebase security rules data-allow destination any
    set rulebase security rules data-allow application any 
    set rulebase security rules data-allow service any
    set rulebase security rules data-allow action allow
    set rulebase security rules data-allow profile-setting profiles virus default
    set rulebase security rules data-allow profile-setting profiles spyware default
    set rulebase security rules data-allow profile-setting profiles vulnerability default
    ```

> [!CAUTION]  
> This policy allows all traffic and should not be used within production environments.

<br>


## Configure Health Checks

1. In Cloud Shell, retrieve the IP address of the forwarding rule assigned to the load balancer. 

    ```
    gcloud compute forwarding-rules list
    ```

    (output)
    <pre>
    NAME                     REGION    IP_ADDRESS  IP_PROTOCOL  TARGET
    panw-lb-rule-us-west1-a  us-west1  <b>10.0.1.3</b>    UDP          us-west1/panw-lb</pre>

2. Create an address object for the forwarding rule.
    <pre><code>set address <b>gcp-lb-fwd-rule-1</b> ip-netmask <b>10.0.1.3/32</b></code></pre>

3. Configure a loopback interface using the forwarding rule address.

    ```
    set address-group gcp-lb-fwd-rules static [ gcp-lb-fwd-rule-1 ]
    set network interface loopback units loopback.1 ip gcp-lb-fwd-rule-1
    set network virtual-router default interface loopback.1
    set zone gcp-lb-check network layer3 loopback.1
    set network interface loopback units loopback.1 interface-management-profile gcp-lb-profile
    ```

4. Commit the changes.

    ```
    commit
    ```

5. Enter `exit` twice to close the session with the firewall.

> [!TIP]
> For multi-zone deployments, repeat steps **2-3** by assigning a loopback interface to each new forwarding rule. 
