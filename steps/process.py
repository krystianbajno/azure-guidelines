from sources.transform import azure_security_benchmark
from sources.transform import cis_security_benchmark
from sources.transform import nist_sp
from sources.transform import scuba

def process():
  azure_security_benchmark.parse()
  cis_security_benchmark.parse()
  nist_sp.parse()
  scuba.parse()


if __name__ == "__main__":
    process()