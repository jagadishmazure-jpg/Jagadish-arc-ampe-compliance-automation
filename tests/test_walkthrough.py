"""The IA-02 walkthrough in docs/AUDIT_AUTOMATION_EXPLAINED.md prints real, stable facts."""
import pytest

from arcampe import walkthrough


@pytest.mark.parametrize("step", list(walkthrough.STEPS))
def test_every_step_runs(step, capsys):
    walkthrough.STEPS[step]()
    assert capsys.readouterr().out.strip()


def test_checks_story(capsys):
    walkthrough.checks()
    out = capsys.readouterr().out
    assert "AZ-11 stlhxreports  FAIL" in out and "ID-01 directory     PASS" in out
    assert "IA-02 family findings: 12 (11 pass, 1 fail)" in out


def test_policy_flags_the_same_resource(capsys):
    walkthrough.policy()
    out = capsys.readouterr().out
    assert "default effect: Audit" in out and "flags: ['stlhxreports']" in out


def test_agent_story(capsys):
    walkthrough.agent()
    out = capsys.readouterr().out
    assert "[PHONE]" in out and "555-201-3344" not in out
    assert out.count("refused") == 2 and "(isso): approved" in out and "injection test: blocked" in out


def test_binder_tamper_detected(capsys):
    walkthrough.binder()
    out = capsys.readouterr().out
    assert "verify: intact" in out and "after editing one POA&M status: ['02_poam/poam.csv']" in out


def test_checklist_labels_are_computed():
    from arcampe import labels
    for _, ctl, test in walkthrough.CHECKLIST:
        lab = labels.label_for(ctl.split(",")[0].strip())
        assert (lab == "automated") == (not test.startswith("none"))
