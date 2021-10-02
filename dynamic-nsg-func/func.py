import io
import json
import logging
import oci

from fdk import response


def handler(ctx, data: io.BytesIO = None):
    name = "World"
    try:
        body = json.loads(data.getvalue())
        name = body.get("name")
    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))

    logging.getLogger().info("Inside Python Hello World function")
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "One day I will grow up and be a dynamic nsg {0}".format(name)}),
        headers={"Content-Type": "application/json"}
    )


##########################################################################
# Create Resource Principal Signer for Authentication
##########################################################################
def do(signer):
    # List VCNs --------------------------------------------------------
    client = oci.core.VirtualNetworkClient({}, signer=signer)
    try:
        vcns = client.list_vcns(signer.compartment_id)
        vcns = [[v.id, v.display_name] for v in vcns.data]
    except Exception as e:
        vcns = str(e)
    return {"vcns": vcns, }
