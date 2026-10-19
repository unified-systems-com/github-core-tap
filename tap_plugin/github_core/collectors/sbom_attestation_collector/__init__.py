"""SBOM attestation collector: fetch, verify and feed CI-signed CycloneDX SBOMs to the vulnerability mapping.

Spec: specs/spec-github-core-v0.md (req-github-core-sbom-attestations).

The pure parts (config, trust list, revision choice, the pipeline) import no Django and open no socket; the
two seams a caller swaps are the verifier (``verifier.py``) and the lister (``lister.py``).
"""
