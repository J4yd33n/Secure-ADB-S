COMPLIANCE = [
    {
        "attack": "TCP_FLOOD",
        "nist": "DE.AE – Anomalies & Events",
        "icao": "Annex 17 – Security Management"
    },
    {
        "attack": "AIRCRAFT_SPOOFING",
        "nist": "DE.CM – Continuous Monitoring",
        "icao": "Annex 10 – Surveillance Systems"
    },
    {
        "attack": "INVALID_MODE_S",
        "nist": "PR.DS – Data Security",
        "icao": "Annex 10 – Aircraft Identification"
    }
]

def get_compliance():
    return COMPLIANCE
