import pytest
from routes.test_routes import SecurityBatteryRunner

@pytest.fixture
def runner():
    return SecurityBatteryRunner()

def test_scenario_1_incorrect_password(runner):
    res = runner.scenario_1()
    assert res["status"] == "PASS"

def test_scenario_2_invalid_smart_card_fuzzy(runner):
    res = runner.scenario_2()
    assert res["status"] == "PASS"

def test_scenario_3_scad_repeated_failures_lock(runner):
    res = runner.scenario_3()
    assert res["status"] == "PASS"

def test_scenario_4_invalid_ring_lwe_response(runner):
    res = runner.scenario_4()
    assert res["status"] == "PASS"

def test_scenario_5_authentication_bypass_prevention(runner):
    res = runner.scenario_5()
    assert res["status"] == "PASS"

def test_scenario_6_session_expiry_and_revocation(runner):
    res = runner.scenario_6()
    assert res["status"] == "PASS"

def test_scenario_7_audit_log_completeness(runner):
    res = runner.scenario_7()
    assert res["status"] == "PASS"

def test_scenario_8_sensitive_data_leakage_audit(runner):
    res = runner.scenario_8()
    assert res["status"] == "PASS"

def test_scenario_9_honey_token_tripwire(runner):
    res = runner.scenario_9()
    assert res["status"] == "PASS"

def test_complete_security_battery_all_passed(runner):
    res = runner.run_all()
    assert res["all_passed"] is True
    assert res["passed_count"] == 9
