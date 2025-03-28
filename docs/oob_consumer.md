# NSI Out-of-Band - Consumer

## 1. Create Mirroring Endpoint & Endpoint Group

Create an mirroring *endpoint* and *endpoint group* and associate it with the producer's mirroring *deployment group*.  Then, connect the *endpoint group* to the `consumer-vpc` via an endpoint group association. 

1. Create an mirroring endpoint group (`pan-epg`) referencing the producer's deployment group (`pan-dg`). 

    ```
    gcloud network-security mirroring-endpoint-groups create panw-epg \
        --mirroring-deployment-group panw-dg \
        --project $CONSUMER_PROJECT \
        --location global \
        --no-async
    ```

2. Associate the mirroring endpoint group with your consumer’s VPC network.

    ```
    gcloud network-security mirroring-endpoint-group-associations create panw-epg-assoc \
        --mirroring-endpoint-group panw-epg \
        --network consumer-vpc \
        --project $CONSUMER_PROJECT \
        --location global \
        --no-async
    ``` 
<br>

## 2. Create Mirroring Rules

Create a `custom-mirroring` security profile group, configure a network firewall policy with rules that use this group as the `ACTION`, and finally, associate the network firewall policy with your `consumer-vpc` network. 

1. Create `custom-mirroring` security profile (`pan-sp`) referencing the mirroring endpoint group (`panw-epg`).  

    ```
    gcloud network-security security-profiles custom-mirroring create panw-sp \
        --mirroring-endpoint-group panw-epg \
        --billing-project $CONSUMER_PROJECT \
        --organization $ORG_ID \
        --location global
    ```

2. Add the security profile to a security profile group (`pan-spg`).

    ```
    gcloud network-security security-profile-groups create panw-spg \
        --custom-mirroring-profile panw-sp \
        --billing-project $CONSUMER_PROJECT \
        --organization $ORG_ID \
        --location global
    ```

3. Create a network firewall policy (`consumer-policy`).  
   
    ```
    gcloud compute network-firewall-policies create consumer-policy \
        --project $CONSUMER_PROJECT \
        --global
    ```


4. Within the network firewall policy, create two mirroring rules to mirror all `INGRESS` and `EGRESS` traffic by setting the security profile group as the action within each rule.  
   
    ```
    gcloud compute network-firewall-policies mirroring-rules create 10 \
        --action mirror \
        --firewall-policy consumer-policy \
        --global-firewall-policy \
        --security-profile-group organizations/$ORG_ID/locations/global/securityProfileGroups/panw-spg \
        --layer4-configs all \
        --src-ip-ranges 0.0.0.0/0 \
        --dest-ip-ranges 0.0.0.0/0 \
        --direction INGRESS

    gcloud compute network-firewall-policies mirroring-rules create 11 \
        --action mirror \
        --firewall-policy consumer-policy \
        --global-firewall-policy \
        --security-profile-group organizations/$ORG_ID/locations/global/securityProfileGroups/panw-spg \
        --layer4-configs all \
        --src-ip-ranges 0.0.0.0/0 \
        --dest-ip-ranges 0.0.0.0/0 \
        --direction EGRESS
    ```

5. Associate the network firewall policy to the `consumer-vpc` network.  
   
    ```
    gcloud compute network-firewall-policies associations create \
        --name consumer-policy-assoc \
        --global-firewall-policy \
        --firewall-policy consumer-policy \
        --network consumer-vpc \
        --project $CONSUMER_PROJECT
    ```

6. <b>Proceed to [Test Inspection](../#test-inspection).</b>

<br>

---

## Delete Consumer Resources

1. Delete the mirroring security profile, firewall policy, endpoint, & endpoint association. 

    ```
    gcloud compute network-firewall-policies associations delete \
        --project=$CONSUMER_PROJECT \
        --name=consumer-policy-assoc \
        --firewall-policy=consumer-policy \
        --global-firewall-policy

    gcloud compute network-firewall-policies delete consumer-policy \
        --project=$CONSUMER_PROJECT \
        --global

    gcloud network-security security-profile-groups delete panw-spg \
        --organization $ORG_ID \
        --location=global \
        --quiet

    gcloud network-security mirroring-endpoint-group-associations delete panw-epg-assoc \
        --project $CONSUMER_PROJECT \
        --location global \
        --no-async

    gcloud network-security mirroring-endpoint-groups delete panw-epg \
        --project $CONSUMER_PROJECT \
        --location global \
        --no-async

    gcloud network-security security-profiles custom-mirroring delete panw-sp \
        --organization $ORG_ID \
        --location=global \
        --quiet
    ```

3. Run `terraform destroy` from the `consumer` directory.

    ```
    cd
    cd google-cloud-nsi-tutorial/consumer
    terraform destroy
    ```

4. Enter `yes` to delete all consumer resources.

5. To delete the producer, proceed to [Out-of-Band: Delete Producer Resources](oob_producer.md#delete-producer-resources).