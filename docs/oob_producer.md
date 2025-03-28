# NSI Out-of-Band - Producer

## Create Mirroring Deployment & Deployment Group
Create an mirroring deployment for the zone you wish to inspect traffic (`$ZONE`). and add it to an mirroring deployment group.

1. Create an mirroring deployment group (`panw-dg`) within the firewall’s `data-vpc`.

    ```
    gcloud network-security mirroring-deployment-groups create panw-dg \
        --location global \
        --project $PRODUCER_PROJECT \
        --network $DATA_VPC \
        --no-async
    ```

2. Create and configure a forwarding rule (`panw-lb-rule-$ZONE`) as a *mirroring collector* for the internal load balancer.

    ```
    gcloud compute forwarding-rules create panw-lb-rule-$ZONE \
        --load-balancing-scheme=INTERNAL \
        --ip-protocol=UDP \
        --ports=6081 \
        --backend-service=$BACKEND_SERVICE \
        --subnet=$DATA_SUBNET \
        --region=$REGION \
        --project=$PRODUCER_PROJECT \
        --is-mirroring-collector
    ```

3. Create a mirroring deployment (`panw-deployment-$ZONE`) by associating it with your forwarding rule.

    ```
    gcloud network-security mirroring-deployments create panw-deployment-$ZONE \
        --location $ZONE \
        --forwarding-rule panw-lb-rule-$ZONE \
        --forwarding-rule-location $REGION \
        --mirroring-deployment-group projects/$PRODUCER_PROJECT/locations/global/mirroringDeploymentGroups/panw-dg \
        --no-async
    ```

> [!TIP]
> In this tutorial, all of the consumer resources are in one zone, requiring only one mirroring deployment. For multiple zones, repeat steps **3-4** for each zone requiring inspection. 

3. <b>Proceed to [Configure Firewall](../#configure-firewall).</b>

<br>

---

## Delete Producer Resources

1. Delete the mirroring deployment, forwarding rule, and mirroring deployment group. 

    ```
    gcloud beta network-security mirroring-deployments delete panw-deployment-$ZONE \
        --location $ZONE \
        --no-async

    gcloud compute forwarding-rules delete panw-lb-rule-$ZONE \
        --project $PRODUCER_PROJECT \
        --region $REGION \
        --quiet

    gcloud beta network-security mirroring-deployment-groups delete panw-dg \
        --location global \
        --project $PRODUCER_PROJECT \
        --no-async
    ```

2. Run `terraform destroy` from the `/producer` directory.

    ```
    cd
    cd google-cloud-nsi-tutorial/producer
    terraform destroy
    ```

3. Enter `yes` to delete all producer resources.
