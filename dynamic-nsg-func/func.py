import io
import json

from fdk import response
import oci

def handler(ctx, data: io.BytesIO=None):
    signer = oci.auth.signers.get_resource_principals_signer()
    resp = do(signer)
    return response.Response(ctx,
        response_data=json.dumps(resp),
        headers={"Content-Type": "application/json"} )

def do(signer):
    # List VCNs --------------------------------------------------------
    client = oci.core.VirtualNetworkClient({}, signer=signer)
    try:
        vcns = client.list_vcns(signer.compartment_id)
        vcns = [[v.id, v.display_name] for v in vcns.data]
    except Exception as e:
        vcns = str(e)
    return {"vcns": vcns, }