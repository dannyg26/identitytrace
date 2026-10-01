from infra.azure.check_region import check_capabilities


def test_restricted_offer_fails_despite_fast_provisioning_entries():
    errors = check_capabilities([{
        "reason": "Provisioning is restricted in this region",
        "supportedFeatures": [{"name": "OfferRestricted", "status": "Enabled"}],
        "supportedServerVersions": [], "supportedServerEditions": [],
        "supportedFastProvisioningEditions": [{"supportedSku": "standard_b1ms"}],
    }])
    assert len(errors) == 3
    assert "restricted" in errors[0]


def test_required_version_and_sku_are_available():
    assert not check_capabilities([{
        "supportedFeatures": [{"name": "OfferRestricted", "status": "Disabled"}],
        "supportedServerVersions": [{"name": "17"}],
        "supportedServerEditions": [{"supportedServerSkus": [{"name": "Standard_B1ms"}]}],
    }])


def test_empty_capabilities_fail_closed():
    assert check_capabilities([])
