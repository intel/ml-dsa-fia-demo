# ML-DSA FIA Demo
:warning: **This code is for demonstrative purposes!** :warning:

This code demonstrates fault injection analysis (FIA) attacks and countermeasures on Module Lattice Digital Signature Algorithm 
(ML-DSA). ML-DSA is based on [Dilithium](https://pq-crystals.org/dilithium/).

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/intel/ml-dsa-fia-demo/HEAD)

## Environment

### Local Environment
* Install your favorite distribution of Python (e.g., [Python](https://www.python.org/downloads/))
  * This code was tested using Python 3.11.4 and 3.12.3
* Install your favorite text editor or IDE (e.g., [Jupiter](https://jupyter.org/install), [PyCharm](https://www.jetbrains.com/pycharm/download/?section=windows))
* Clone this repository
```commandline
git clone --recurse-submodules https://github.com/intel/ml-dsa-fia-demo.git
```
* Install the required packages
```commandline
pip install -r requirements.txt
```
* Run the notebooks
```commandline
jupyter notebook demo/demo-attacker.ipynb
jupyter notebook demo/demo-signer.ipynb
```

### Cloud Environment
1. Go to [binder](https://mybinder.org/)
2. Paste the link to this repository (i.e., `https://github.com/intel/ml-dsa-fia-demo`) in the `GitHub repository name or URL` field
3. Click on `launch`

## Notes
* The provided code does not work, but it can be made to work with a few changes. Follow the instructions and fix the code in [demo/demo-attacker.ipynb](demo/demo-attacker.ipynb) and [demo/demo-signer.ipynb](demo/demo-signer.ipynb).
* Alternatively, you can use and modify the code in [demo/attacker.py](demo/attacker.py) and [demo/signer.py](demo/signer.py). You can run the scripts or the notebooks [demo/attacker.ipynb](demo/attacker.ipynb) and [demo/signer.ipynb](demo/signer.ipynb).

## References
* [Loop-Abort Faults on Lattice-Based Fiat–Shamir and Hash-and-Sign Signatures](https://eprint.iacr.org/2016/449.pdf), SAC 2016
* [CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme](https://tches.iacr.org/index.php/TCHES/article/view/839/791), TCHES 2018
* [Differential Fault Attacks on Deterministic Lattice Signatures](https://eprint.iacr.org/2018/355.pdf), TCHES 2018
* [Exploiting Determinism in Lattice-based Signatures](https://eprint.iacr.org/2019/769.pdf), AsiaCCS 2019
* [FIPS 204 (Draft): Module-Lattice-Based Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf), NIST 2023
* [Loop Aborts Strike Back: Defeating Fault Countermeasures in Lattice Signatures with ILP](https://tches.iacr.org/index.php/TCHES/article/view/11170/10609), TCHES 2023
