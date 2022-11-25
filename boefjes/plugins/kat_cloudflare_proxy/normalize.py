import json
from typing import Iterator, Union

from octopoes.models import OOI, Reference
from octopoes.models.ooi.findings import CVEFindingType, Finding
from octopoes.models.ooi.network import IPPort, Protocol, PortState

from boefjes.job_models import NormalizerMeta

def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterator[OOI]:
    results = json.loads(raw)
    ooi = Reference.from_str(normalizer_meta.boefje_meta.input_ooi)
    for result in results:

        # yield id info
        # yield if broken proxy
        # yield if bypassed proxy
